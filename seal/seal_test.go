package seal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"filippo.io/edwards25519"

	"glyph/identity"
)

func TestX25519MatchesEd25519(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	xPriv, err := edPrivToX(id.Private())
	if err != nil {
		t.Fatal(err)
	}
	xPub, err := edPubToX(id.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(xPriv.PublicKey().Bytes(), xPub.Bytes()) {
		t.Fatal("Ed25519 key does not convert to the matching X25519 key")
	}
	p, err := new(edwards25519.Point).SetBytes(id.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(xPub.Bytes(), p.BytesMontgomery()) {
		t.Fatal("public conversion != BytesMontgomery")
	}
}

func TestSealOpenChat(t *testing.T) {
	alice := mustID(t)
	bob := mustID(t)
	text := "unique-plaintext-marker-9f3a"
	blob, err := Seal(alice.Private(), bob.ID(), Message{
		Kind: KindChat, Counter: 1, Unix: 99, Text: text,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(text)) {
		t.Fatal("plaintext is visible in the blob")
	}
	if bytes.Contains(blob[:headerLen], alice.Public()) || bytes.Contains(blob[:headerLen], bob.Public()) {
		t.Fatal("glyph id is in the clear header")
	}
	got, err := Open(bob.Private(), blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sender != alice.ID() || got.Recipient != bob.ID() || got.Text != text || got.Counter != 1 || got.Unix != 99 || got.Kind != KindChat {
		t.Fatalf("opened %#v", got)
	}
	if _, err := Open(alice.Private(), blob); !errors.Is(err, ErrTruncated) {
		t.Fatalf("sender opened the letter: %v", err)
	}
}

func TestSealOpenSuccessor(t *testing.T) {
	alice := mustID(t)
	bob := mustID(t)
	next := mustID(t)
	sig, err := SignSuccessor(next.Private(), alice.ID(), bob.ID(), next.ID())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(alice.Private(), bob.ID(), Message{
		Kind: KindSuccessor, Counter: 4, Unix: 3, Next: next.ID(), NextSig: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(next.ID())) {
		t.Fatal("successor id is visible in the blob")
	}
	if bytes.Contains(blob[:headerLen], next.Public()) || bytes.Contains(blob[:headerLen], alice.Public()) || bytes.Contains(blob[:headerLen], bob.Public()) {
		t.Fatal("glyph id is in the clear header")
	}
	got, err := Open(bob.Private(), blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindSuccessor || got.Next != next.ID() || got.Sender != alice.ID() || got.Counter != 4 {
		t.Fatalf("opened %#v", got)
	}
	if err := VerifySuccessor(got.Sender, got.Recipient, got.Next, got.NextSig); err != nil {
		t.Fatal(err)
	}
}

func TestSuccessorRejectsUnsigned(t *testing.T) {
	alice := mustID(t)
	bob := mustID(t)
	next := mustID(t)
	_, err := Seal(alice.Private(), bob.ID(), Message{
		Kind: KindSuccessor, Counter: 1, Unix: 1, Next: next.ID(),
	})
	if !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsigned successor err=%v", err)
	}
	sig, err := SignSuccessor(alice.Private(), alice.ID(), bob.ID(), next.ID())
	if err == nil || sig != nil {
		t.Fatal("the current key signed as the next key")
	}
}

func TestRejectBadSignature(t *testing.T) {
	alice := mustID(t)
	bob := mustID(t)
	other := mustID(t)
	msg := Message{Kind: KindChat, Counter: 1, Unix: 1, Text: "hi"}
	payload, err := encodePayload(msg)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(other.Private(), sigInput(alice.Public(), bob.Public(), payload))
	blob, err := encryptSigned(alice.Public(), bob.Public(), sig, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(bob.Private(), blob)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err=%v", err)
	}
}

func TestRejectSwappedRecipient(t *testing.T) {
	alice := mustID(t)
	bob := mustID(t)
	carol := mustID(t)
	blob, err := Seal(alice.Private(), bob.ID(), Message{
		Kind: KindChat, Counter: 1, Unix: 1, Text: "for bob",
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob[:headerLen], alice.Public()) || bytes.Contains(blob[:headerLen], bob.Public()) {
		t.Fatal("glyph id is in the clear header")
	}
	if _, err := Open(carol.Private(), blob); !errors.Is(err, ErrTruncated) {
		t.Fatalf("carol opened bob's letter: %v", err)
	}
	mut := append([]byte(nil), blob...)
	mut[1] ^= 0xff
	if _, err := Open(bob.Private(), mut); err == nil {
		t.Fatal("mutated ephemeral key was accepted")
	}
}

func TestRejectTruncatedBlob(t *testing.T) {
	alice := mustID(t)
	bob := mustID(t)
	blob, err := Seal(alice.Private(), bob.ID(), Message{
		Kind: KindChat, Counter: 1, Unix: 1, Text: "hello from alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	cuts := [][]byte{nil, blob[:10], blob[:len(blob)/2], blob[:len(blob)-1]}
	for _, cut := range cuts {
		_, err := Open(bob.Private(), cut)
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("cut len %d err=%v", len(cut), err)
		}
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
