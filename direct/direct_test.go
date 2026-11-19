package direct

import (
	"bytes"
	"testing"

	"glyph/identity"
)

func TestDialAllowsPublicAndRejectsUnspecified(t *testing.T) {
	if err := ValidateDial("8.8.8.8:7421"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDial("example.com:7421"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDial("127.0.0.1:9"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "example.com", "0.0.0.0:7421", "224.0.0.1:7421", "8.8.8.8:0", "bad host:7421", "http://example.com:80"} {
		if err := ValidateDial(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

func TestInternetDialPinsTheGlyphID(t *testing.T) {
	alice := mustID(t)
	bob := mustID(t)
	eve := mustID(t)
	var gotPeer string
	var gotBlob []byte
	bobNode := mustNode(t, bob, func() []string { return []string{alice.ID()} }, func(peer string, blob []byte) bool {
		gotPeer = peer
		gotBlob = append([]byte(nil), blob...)
		return true
	})
	aliceNode := mustNode(t, alice, func() []string { return []string{bob.ID()} }, func(string, []byte) bool { return true })
	eveNode := mustNode(t, eve, func() []string { return []string{bob.ID()} }, func(string, []byte) bool { return true })
	if err := aliceNode.SetReach(bob.ID(), bobNode.Addr()); err != nil {
		t.Fatal(err)
	}
	if err := aliceNode.Deliver(bob.ID(), []byte("sealed-letter")); err != nil {
		t.Fatal(err)
	}
	if gotPeer != alice.ID() || !bytes.Equal(gotBlob, []byte("sealed-letter")) {
		t.Fatalf("bob received %s %q", gotPeer, gotBlob)
	}
	if err := bobNode.Deliver(alice.ID(), []byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := eveNode.SetReach(bob.ID(), bobNode.Addr()); err != nil {
		t.Fatal(err)
	}
	if err := eveNode.Deliver(bob.ID(), []byte("intruder")); err == nil {
		t.Fatal("bob accepted a glyph ID he had not added")
	}
	if err := aliceNode.SetReach(bob.ID(), "8.8.8.8:1"); err != nil {
		t.Fatal("a public address the user typed was rejected")
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

func mustNode(t *testing.T, id *identity.Identity, friends func() []string, on func(string, []byte) bool) *Node {
	t.Helper()
	n, err := Listen("127.0.0.1:0", id, friends, on)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}
