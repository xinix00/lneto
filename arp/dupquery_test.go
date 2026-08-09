package arp

import (
	"testing"
)

// TestReplyResolvesAllPendingQueries: two independent queriers ask for the
// same address (a background gateway resolve racing a dial to that same
// host); the single ARP reply must resolve BOTH cache entries. Resolving
// only the first left the second querier re-ARPing an already-answered
// address until its deadline.
func TestReplyResolvesAllPendingQueries(t *testing.T) {
	var h Handler
	err := h.Reset(HandlerConfig{
		HardwareAddr:  []byte{2, 0, 0, 0, 0, 9},
		ProtocolAddr:  []byte{10, 100, 0, 2},
		MaxQueries:   8,
		MaxPending:   8,
		HardwareType: 1,
		ProtocolType: 0x0800,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := []byte{10, 100, 0, 1}
	var resolves int
	h.SetOnResolveCallback(func(hwAddr, protoAddr []byte) { resolves++ })
	if err := h.StartQuery(target, true); err != nil {
		t.Fatal(err)
	}
	if err := h.StartQuery(target, true); err != nil {
		t.Fatal(err)
	}

	// Het antwoord, in het klassieke 42-byte formaat (na de ethernet-kop).
	reply := make([]byte, 28)
	reply[0], reply[1] = 0, 1 // htype ethernet
	reply[2], reply[3] = 8, 0 // ptype ipv4
	reply[4], reply[5] = 6, 4
	reply[6], reply[7] = 0, 2 // reply
	copy(reply[8:14], []byte{2, 0, 0, 0, 0, 0})
	copy(reply[14:18], target)
	copy(reply[18:24], []byte{2, 0, 0, 0, 0, 9})
	copy(reply[24:28], []byte{10, 100, 0, 2})
	if err := h.Demux(reply, 0); err != nil {
		t.Fatal(err)
	}
	if resolves != 2 {
		t.Fatalf("resolve callbacks = %d, want 2 (both pending queries)", resolves)
	}
}
