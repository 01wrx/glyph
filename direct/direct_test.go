package direct

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"glyph/identity"
)

func TestBeaconRejectsForgeryAndPublicAddress(t *testing.T) {
	alice := mustID(t)
	bob := mustID(t)
	eve := mustID(t)
	var nonce [16]byte
	nonce[0] = 7
	now := time.Unix(1_700_000_000, 0)
	good := packBeacon(alice.Private(), "192.168.1.20:7422", now.Unix(), nonce[:])
	id, addr, ok := openBeacon(good, now, []ed25519.PublicKey{bob.Public(), alice.Public()})
	if !ok || id != alice.ID() || addr != "192.168.1.20:7422" {
		t.Fatalf("beacon %s %s %v", id, addr, ok)
	}
	if _, _, ok := openBeacon(good, now, []ed25519.PublicKey{bob.Public()}); ok {
		t.Fatal("another key recognized the announcement")
	}
	pub := packBeacon(eve.Private(), "8.8.8.8:80", now.Unix(), nonce[:])
	if _, _, ok := openBeacon(pub, now, []ed25519.PublicKey{eve.Public()}); ok {
		t.Fatal("public address was accepted")
	}
	if _, _, ok := openBeacon(good, now.Add(3*time.Minute), []ed25519.PublicKey{alice.Public()}); ok {
		t.Fatal("stale announcement was accepted")
	}
	good[len(good)-1] ^= 1
	if _, _, ok := openBeacon(good, now, []ed25519.PublicKey{alice.Public()}); ok {
		t.Fatal("altered announcement was accepted")
	}
}

func TestDeliverRequiresThePeerKey(t *testing.T) {
	alice := mustID(t)
	bob := mustID(t)
	eve := mustID(t)
	aliceFriends := func() []string { return []string{bob.ID()} }
	bobFriends := func() []string { return []string{alice.ID()} }
	eveFriends := func() []string { return nil }
	var gotPeer string
	var gotBlob []byte
	bobNode := mustNode(t, bob, bobFriends, func(peer string, blob []byte) {
		gotPeer = peer
		gotBlob = append([]byte(nil), blob...)
	})
	aliceNode := mustNode(t, alice, aliceFriends, func(string, []byte) {})
	eveNode := mustNode(t, eve, eveFriends, func(string, []byte) {})
	bobNode.SetFind(20 * time.Millisecond)
	aliceNode.SetFind(20 * time.Millisecond)
	if aliceNode.Deliver(bob.ID(), []byte("sealed")) == nil {
		t.Fatal("delivered before bob announced himself")
	}
	if !aliceNode.AcceptBeacon(bobNode.Beacon()) {
		t.Fatal("bob's announcement was rejected")
	}
	if err := aliceNode.Deliver(bob.ID(), []byte("sealed-letter")); err != nil {
		t.Fatal(err)
	}
	if gotPeer != alice.ID() || !bytes.Equal(gotBlob, []byte("sealed-letter")) {
		t.Fatalf("bob received %s %q", gotPeer, gotBlob)
	}
	if eveNode.AcceptBeacon(bobNode.Beacon()) {
		t.Fatal("eve recognized a glyph ID eve was not given")
	}
	eveNode.mu.Lock()
	eveNode.peers[bob.ID()] = sight{addr: bobNode.Addr(), until: time.Now().Add(time.Minute)}
	eveNode.mu.Unlock()
	if err := eveNode.Deliver(bob.ID(), []byte("intruder")); err == nil {
		t.Fatal("bob accepted a glyph ID he had not added")
	}
}

func mustID(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustNode(t *testing.T, id *identity.Identity, friends func() []string, on func(string, []byte)) *Node {
	t.Helper()
	n, err := Listen(id, friends, on)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}
