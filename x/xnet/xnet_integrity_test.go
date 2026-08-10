package xnet

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

// TestTCPStreamIntegrityUnderLoss pins the promise a TCP stream makes: the
// bytes that arrive are the bytes that were sent, in order, however the
// network mangles the packets carrying them. Loss is the interesting case
// here because it is the ordinary case on real hardware: a NIC whose receive
// ring runs dry drops frames without any error indication, and the receiver
// then sees a hole followed by segments it cannot use yet.
//
// Measured on a Sophgo SG2002 (100Mbit, DWMAC) on 2026-08-10: a 16 MiB
// download arrived with the full length but a different SHA-256, and a TLS
// transfer over the same path failed with "bad record MAC" — two independent
// witnesses of corruption, while the same board's transmit path was
// bit-perfect. This test reproduces that shape in-process: the pump drops
// every Nth frame, so the receiver is continuously fed out-of-order segments.
//
// A stream that is short, hangs, or resets is a different (and lesser)
// failure than one that completes with wrong bytes: silent corruption is
// what an application cannot defend against, so the assertion is on content
// first and length second.
func TestTCPStreamIntegrityUnderLoss(t *testing.T) {
	testStreamIntegrity(t, mangleDrop)
}

// TestTCPStreamIntegrityUnderReorder is the sharper of the two: no frame is
// ever lost, only delayed past its successor. Nothing has to be retransmitted,
// so what it exercises is purely the out-of-order path — segments staged in
// the receive ring's free region and committed once the gap fills. The staging
// keeps no buffer offset ("the ring write pointer advances in lockstep with
// rcv.NXT, so the staged bytes are always where seq implies"), and this test
// is what holds that invariant to account.
func TestTCPStreamIntegrityUnderReorder(t *testing.T) {
	testStreamIntegrity(t, mangleReorder)
}

// How the pump mistreats server→client frames.
type mangleMode int

const (
	mangleDrop    mangleMode = iota // every Nth frame is never delivered
	mangleReorder                   // every Nth frame is delayed one frame
)

func testStreamIntegrity(t *testing.T, mode mangleMode) {
	const (
		MTU      = ethernet.MaxMTU
		svPort   = 80
		total    = 512 << 10 // enough to wrap the receive ring many times
		chunk    = 4 << 10
		bufSize  = 8 << 10 // small on purpose: forces ring wrap-around
		dropEver = 23      // mangle every Nth data-carrying frame
	)

	client, sv := new(StackAsync), new(StackAsync)
	if err := client.Reset(StackConfig{
		Hostname:          "integrity-client",
		RandSeed:          99,
		StaticAddress4:    [4]byte{10, 0, 0, 80},
		MaxActiveTCPPorts: 4,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 80},
		MTU:               MTU,
		ICMPQueueLimit:    2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sv.Reset(StackConfig{
		Hostname:          "integrity-server",
		RandSeed:          ^int64(99),
		StaticAddress4:    [4]byte{10, 0, 0, 81},
		MaxActiveTCPPorts: 4,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 81},
		MTU:               MTU,
		ICMPQueueLimit:    2,
	}); err != nil {
		t.Fatal(err)
	}
	client.SetGatewayHardwareAddr(sv.HardwareAddr())
	sv.SetGatewayHardwareAddr(client.HardwareAddr())

	pool := func(established time.Duration) TCPPoolConfig {
		return TCPPoolConfig{
			PoolSize: 2, QueueSize: 8,
			TxBufSize: bufSize, RxBufSize: bufSize,
			EstablishedTimeout: established,
			ClosingTimeout:     established,
			NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
		}
	}
	svGo := sv.StackBlocking(backoffYield).StackGo(StackGoConfig{
		ListenerPoolConfig: pool(30 * time.Second),
	})
	clGo := client.StackBlocking(backoffYield).StackGo(StackGoConfig{
		ListenerPoolConfig: pool(30 * time.Second),
		TCPDialTimeout:     2 * time.Second,
		TCPDialRetries:     2,
	})

	lsAny, err := svGo.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM,
		netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort), netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	listener := lsAny.(net.Listener)
	defer listener.Close()

	// The payload is deterministic (xorshift64, seed "HPOS") so a mismatch can
	// be reported as a position, not just as "differs" — where a stream first
	// diverges is the whole diagnosis.
	want := make([]byte, total)
	x := uint64(0x48504f53)
	for i := range want {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		want[i] = byte(x)
	}

	served := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(60 * time.Second))
		for off := 0; off < total; off += chunk {
			end := min(off+chunk, total)
			if _, err := c.Write(want[off:end]); err != nil {
				served <- err
				return
			}
		}
		served <- nil
	}()

	// The pump moves frames between the two stacks and mistreats every
	// dropEver'th server→client frame. Only the data direction is touched, so
	// the receiver's own ACKs always arrive — that keeps the test honest about
	// what it claims to exercise.
	var mangled, svTx, clTx atomic.Int64
	stopPump := make(chan struct{})
	defer close(stopPump)
	go func() {
		buf := make([]byte, MTU+ethernet.MaxOverheadSize)
		held := make([]byte, 0, MTU+ethernet.MaxOverheadSize) // the delayed frame
		seen := 0
		for {
			select {
			case <-stopPump:
				return
			default:
			}
			moved := false
			if n, err := client.EgressEthernet(buf); err == nil && n > 0 {
				clTx.Add(1)
				sv.IngressEthernet(buf[:n])
				moved = true
			}
			if n, err := sv.EgressEthernet(buf); err == nil && n > 0 {
				svTx.Add(1)
				seen++
				switch {
				case seen%dropEver != 0:
					client.IngressEthernet(buf[:n])
					// A frame held from the previous round now arrives late,
					// i.e. after its successor: pure reordering, no loss.
					if len(held) > 0 {
						client.IngressEthernet(held)
						held = held[:0]
					}
				case mode == mangleDrop:
					mangled.Add(1) // consumed and never delivered
				default: // mangleReorder
					held = append(held[:0], buf[:n]...)
					mangled.Add(1)
				}
				moved = true
			}
			if !moved {
				runtime.Gosched()
			}
		}
	}()

	// An independent monitor: the reader below blocks, so it cannot report on
	// its own stall. This says whether frames keep flowing while no byte is
	// delivered — a silent sender and a refusing receiver need opposite fixes.
	var rxBytes atomic.Int64
	go func() {
		prevSv, prevCl, prevRx := int64(0), int64(0), int64(0)
		for {
			select {
			case <-stopPump:
				return
			default:
			}
			time.Sleep(2 * time.Second)
			svN, clN, rxN := svTx.Load(), clTx.Load(), rxBytes.Load()
			t.Logf("monitor: rx=%d (+%d)  sv->cl=%d (+%d)  cl->sv=%d (+%d)  mangled=%d",
				rxN, rxN-prevRx, svN, svN-prevSv, clN, clN-prevCl, mangled.Load())
			prevSv, prevCl, prevRx = svN, clN, rxN
		}
	}()

	raddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	cAny, err := clGo.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM,
		netip.AddrPort{}, raddr)
	if err != nil {
		t.Fatal(err)
	}
	conn := cAny.(net.Conn)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	got := make([]byte, 0, total)
	rb := make([]byte, chunk)
	t0, lastLog, lastLen := time.Now(), time.Now(), 0
	for len(got) < total {
		n, err := conn.Read(rb)
		got = append(got, rb[:n]...)
		rxBytes.Store(int64(len(got)))
		// Progress trace: a stream that stops dead and one that crawls need
		// different fixes, and the difference is invisible in a final verdict.
		if time.Since(lastLog) > 2*time.Second {
			// Frame counters separate the two possible stalls: a sender that
			// stopped transmitting versus a receiver refusing what arrives.
			t.Logf("t=%4.1fs %7d/%d bytes (+%d since last, %d mangled) sv->cl frames=%d cl->sv frames=%d",
				time.Since(t0).Seconds(), len(got), total, len(got)-lastLen, mangled.Load(),
				svTx.Load(), clTx.Load())
			lastLog, lastLen = time.Now(), len(got)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("read stalled after %d/%d bytes (%d frames mangled): %v",
				len(got), total, mangled.Load(), err)
		}
	}
	t.Logf("stream complete in %.1fs (%d frames mangled)", time.Since(t0).Seconds(), mangled.Load())

	// Content first: a wrong byte is worse than a missing one.
	for i := 0; i < min(len(got), total); i++ {
		if got[i] != want[i] {
			t.Errorf("stream corrupted at byte %d of %d: got %#02x want %#02x (%d frames mangled)",
				i, total, got[i], want[i], mangled.Load())
			// How it diverges is the diagnosis: a stream that resumes at a
			// shift carries duplicated (or missing) bytes — the receive ring
			// and rcv.NXT moved by different amounts — whereas one that never
			// realigns carries foreign bytes.
			t.Log(describeDivergence(got, want, i))
			t.FailNow()
		}
	}
	if len(got) != total {
		t.Fatalf("stream truncated: %d of %d bytes (%d frames mangled)", len(got), total, mangled.Load())
	}
	if err := <-served; err != nil {
		t.Fatalf("server side: %v", err)
	}
	if mangled.Load() == 0 {
		t.Fatal("no frames were mangled — the test did not exercise recovery")
	}
	t.Logf("%d bytes intact across %d mangled frames", total, mangled.Load())
}

// describeDivergence characterises how got diverges from want at index i. A
// shift means the receiver committed a different number of bytes than the
// sequence space advanced — duplicated bytes if got runs ahead, dropped bytes
// if it lags — which points at the receive ring and rcv.NXT parting company.
// No shift at all means the bytes are foreign to the stream.
func describeDivergence(got, want []byte, i int) string {
	const window = 64
	for shift := 1; shift <= 4096; shift++ {
		for _, s := range [2]int{shift, -shift} {
			if i+s < 0 || i+s+window > len(want) || i+window > len(got) {
				continue
			}
			if string(got[i:i+window]) == string(want[i+s:i+s+window]) {
				kind := "duplicated"
				if s > 0 {
					kind = "missing"
				}
				return fmt.Sprintf("divergence: stream realigns at want[i%+d] — %d bytes %s at byte %d",
					s, abs(s), kind, i)
			}
		}
	}
	return fmt.Sprintf("divergence: no realignment within ±4096 bytes — got % x, want % x",
		got[i:min(i+16, len(got))], want[i:min(i+16, len(want))])
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
