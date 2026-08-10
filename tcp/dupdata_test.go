package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// TestHandlerRejectsDuplicateData is the minimal statement of a stream
// invariant: a segment the receiver has already accepted must not reach the
// receive stream a second time. Retransmissions of already-acknowledged data
// are ordinary TCP — a lost ACK, a spurious RTO, a reordered network — and the
// receiver's duty is to acknowledge them and drop the payload (RFC 9293 §3.10,
// "the segment text is trimmed to the receive window").
//
// The failure this pins is silent: the ControlBlock correctly leaves rcv.NXT
// where it is for a duplicate, but the payload is written into the receive ring
// regardless, so the ring and rcv.NXT part company. The stream that comes out
// has the right length and the wrong bytes — the shape observed on a 16 MiB
// download over a real 100Mbit link on 2026-08-10 (full length, different
// SHA-256, and TLS failing with "bad record MAC").
func TestHandlerRejectsDuplicateData(t *testing.T) {
	const mtu = ethernet.MaxMTU
	const maxpackets = 3
	rng := rand.New(rand.NewSource(7))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)
	setupClientServer(t, rng, client, server)

	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	// One data segment, captured on the wire so it can be replayed verbatim.
	data := []byte("hello")
	if n, err := client.Write(data); err != nil || n != len(data) {
		t.Fatal("client write:", n, err)
	}
	clear(rawbuf[:])
	n, err := client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}
	segment := append([]byte(nil), rawbuf[:n]...)

	if err := server.Recv(segment); err != nil {
		t.Fatal("first delivery:", err)
	}
	// The replay: byte-identical, as a retransmission of acknowledged data is.
	// An error here is acceptable behaviour (the segment may be refused
	// outright); delivering its payload twice is not.
	errDup := server.Recv(append([]byte(nil), segment...))

	got := make([]byte, 64)
	nr, err := server.Read(got)
	if err != nil {
		t.Fatal("server read:", err)
	}
	if nr != len(data) || string(got[:nr]) != string(data) {
		t.Fatalf("duplicate segment reached the stream: server read %d bytes %q, want %d bytes %q (Recv of the duplicate returned %v)",
			nr, got[:nr], len(data), data, errDup)
	}
}
