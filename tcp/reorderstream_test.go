package tcp

import (
	"math/rand"
	"testing"

	"github.com/xinix00/lneto/ethernet"
)

// TestHandlerStreamIntegrityUnderReorder drives one handler pair with a
// hand-controlled arrival order: within each block of shuffleWindow segments,
// arrival order is randomised. Nothing is lost and nothing is retransmitted, so
// the only machinery under test is the staging of early segments in the receive
// ring and their later commit — with several segments staged at once, which a
// single adjacent swap never reaches.
//
// The assertion is byte identity of the reassembled stream. Reordering may
// legitimately cost throughput; it may not change the bytes.
func TestHandlerStreamIntegrityUnderReorder(t *testing.T) {
	const (
		mtu           = ethernet.MaxMTU
		maxpackets    = 8
		segSize       = 100
		nsegs         = 8  // per round; 800 bytes through a 1500-byte ring
		rounds        = 40 // enough for the ring to wrap many times
		shuffleWindow = 4  // segments that may arrive in any order among themselves
	)
	rng := rand.New(rand.NewSource(3))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)
	setupClientServer(t, rng, client, server)
	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	var want, got []byte
	rb := make([]byte, mtu)
	letter := byte('A')
	for round := 0; round < rounds; round++ {
		// Capture this round's segments on the wire, one segment per write.
		segs := make([][]byte, 0, nsegs)
		for i := 0; i < nsegs; i++ {
			payload := make([]byte, segSize)
			for j := range payload {
				payload[j] = letter
			}
			letter++
			if letter > 'Z' {
				letter = 'A'
			}
			if n, err := client.Write(payload); err != nil || n != segSize {
				t.Fatalf("round %d: client write: %d %v", round, n, err)
			}
			clear(rawbuf[:])
			n, err := client.Send(rawbuf[:])
			if err != nil {
				t.Fatalf("round %d: client send: %v", round, err)
			}
			segs = append(segs, append([]byte(nil), rawbuf[:n]...))
			want = append(want, payload...)
		}

		order := make([]int, 0, nsegs)
		for i := 0; i < nsegs; i += shuffleWindow {
			block := make([]int, 0, shuffleWindow)
			for j := i; j < min(i+shuffleWindow, nsegs); j++ {
				block = append(block, j)
			}
			rng.Shuffle(len(block), func(a, b int) { block[a], block[b] = block[b], block[a] })
			order = append(order, block...)
		}

		for _, idx := range order {
			if err := server.Recv(append([]byte(nil), segs[idx]...)); err != nil {
				t.Logf("round %d segment %d refused: %v", round, idx, err)
			}
			// Drain as an application would, keeping the ring from filling.
			for {
				n, err := server.Read(rb)
				if n > 0 {
					got = append(got, rb[:n]...)
				}
				if n == 0 || err != nil {
					break
				}
			}
			// Feed the server's ACKs back so the sender's window keeps opening;
			// without this the test would stall on flow control rather than
			// exercise reassembly.
			clear(rawbuf[:])
			if n, err := server.Send(rawbuf[:]); err == nil && n > 0 {
				client.Recv(rawbuf[:n])
			}
		}

		if string(got) != string(want) {
			// Report at the first divergent round: later rounds pile noise on
			// top of the first mistake.
			i := 0
			for i < len(got) && i < len(want) && got[i] == want[i] {
				i++
			}
			t.Errorf("stream diverges in round %d at byte %d of %d; arrival order %v",
				round, i, len(want), order)
			lo := max(0, i-200)
			t.Errorf("got  %s", summarizeRuns(got[lo:min(len(got), i+200)]))
			t.Errorf("want %s", summarizeRuns(want[lo:min(len(want), i+200)]))
			t.FailNow()
		}
	}
	t.Logf("%d bytes intact across %d rounds of reordering (window %d)", len(got), rounds, shuffleWindow)
}

// summarizeRuns renders a byte stream as run-length pairs ("A×100 B×100"), so a
// duplicated or missing segment is visible at a glance instead of buried in a
// wall of bytes.
func summarizeRuns(b []byte) string {
	out := make([]byte, 0, 64)
	for i := 0; i < len(b); {
		j := i
		for j < len(b) && b[j] == b[i] {
			j++
		}
		out = append(out, b[i], '*')
		out = append(out, []byte(itoa(j-i))...)
		out = append(out, ' ')
		i = j
	}
	return string(out)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var d [8]byte
	i := len(d)
	for v > 0 {
		i--
		d[i] = byte('0' + v%10)
		v /= 10
	}
	return string(d[i:])
}
