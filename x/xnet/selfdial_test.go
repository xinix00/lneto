package xnet

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/xinix00/lneto"
	"github.com/xinix00/lneto/ethernet"
)

// TestStackGoSelfDial has one stack dial its own address; a device-level MAC
// loopback (the way single-NIC hosts implement local delivery) pumps egress
// frames addressed to our own MAC back into ingress and answers ARP for the
// stack's own IP. This needs passive neighbor learning + patchEgressMAC: the
// listener's SYN-ACK carries no per-node MAC, so without the learned entry it
// leaves via the gateway and the handshake never completes.
func TestStackGoSelfDial(t *testing.T) {
	const MTU = ethernet.MaxMTU
	s := new(StackAsync)
	err := s.Reset(StackConfig{
		Hostname:          "self",
		RandSeed:          7,
		StaticAddress4:    [4]byte{10, 0, 0, 60},
		MaxActiveTCPPorts: 8,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 60},
		MTU:               MTU,
		ICMPQueueLimit:    2,
		PassivePeers:      4, // feeds patchEgressMAC: listener replies to the learned MAC
	})
	if err != nil {
		t.Fatal(err)
	}
	// Subnet as any DHCP-configured host would have it: without it neighbor
	// resolution does nothing and the SYN leaves with an unresolved MAC.
	var hostCtl DHCPResults
	hostCtl.Subnet = netip.PrefixFrom(netip.AddrFrom4(s.Addr4()), 24)
	s.AssimilateDHCPResults(&hostCtl)
	// A gateway MAC like any DHCP-configured host has: without it the egress
	// fallback is broadcast and patchEgressMAC's broadcast guard skips the
	// rewrite.
	s.SetGatewayHardwareAddr([6]byte{0x02, 0x99, 0x99, 0x99, 0x99, 0x99})
	sg := s.StackBlocking(backoffYield).StackGo(StackGoConfig{
		ListenerPoolConfig: TCPPoolConfig{
			PoolSize: 8, QueueSize: 4, TxBufSize: MTU, RxBufSize: MTU,
			EstablishedTimeout: 4 * time.Second, ClosingTimeout: time.Second,
			NewBackoff: func() lneto.BackoffStrategy { return backoffYield },
		},
		TCPDialTimeout: 2 * time.Second, TCPDialRetries: 1,
	})
	lsAny, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM,
		netip.AddrPortFrom(netip.AddrFrom4(s.Addr4()), 8080), netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	listener := lsAny.(net.Listener)
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				var b [1]byte
				if _, err := c.Read(b[:]); err == nil {
					c.Write(b[:])
				}
				c.Close()
			}(c)
		}
	}()

	// De locdev-pomp: loopback + ARP-self.
	mac := s.HardwareAddr()
	ip := s.Addr4()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		buf := make([]byte, MTU+ethernet.MaxOverheadSize)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, err := s.EgressEthernet(buf)
			if err != nil || n == 0 {
				runtime.Gosched()
				continue
			}
			f := buf[:n]
			if [6]byte(f[0:6]) == mac {
				if err := s.IngressEthernet(f); err != nil {
					t.Logf("loopback ingress err: %v", err)
				}
				continue
			}
			// ARP request for our own IP: answer it ourselves.
			if n >= 14+28 && f[12] == 0x08 && f[13] == 0x06 {
				a := f[14:]
				if a[6] == 0 && a[7] == 1 && [4]byte(a[24:28]) == ip {
					var r [14 + 28]byte
					copy(r[0:6], a[8:14])
					copy(r[6:12], mac[:])
					r[12], r[13] = 0x08, 0x06
					b := r[14:]
					b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7] = 0, 1, 8, 0, 6, 4, 0, 2
					copy(b[8:14], mac[:])
					copy(b[14:18], ip[:])
					copy(b[18:24], a[8:14])
					copy(b[24:28], a[14:18])
					if err := s.IngressEthernet(r[:]); err != nil {
						t.Logf("arp reply ingress err: %v", err)
					}
					continue
				}
			}
			t.Logf("frame escaped to the wire (%d bytes): dst=%x ethertype=%x", n, f[0:6], f[12:14])
		}
	}()

	raddr := netip.AddrPortFrom(netip.AddrFrom4(ip), 8080)
	cAny, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, netip.AddrPort{}, raddr)
	if err != nil {
		t.Fatalf("self-dial failed: %v", err)
	}
	c := cAny.(net.Conn)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := c.Read(b[:]); err != nil || b[0] != 42 {
		t.Fatalf("echo: %v %d", err, b[0])
	}
	c.Close()
}
