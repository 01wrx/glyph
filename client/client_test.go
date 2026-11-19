package client

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"glyph/identity"
	"glyph/seal"
	"glyph/transcript"

	mbox "glyph-mailbox"
)

func TestCanonicalIDAgreedWithMailbox(t *testing.T) {
	id := mustID(t)
	pub, err := mbox.ParseID(id.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, id.Public()) {
		t.Fatal("mailbox parsed a different key")
	}
	prefix := id.ID()[:len(id.ID())-1]
	if _, err := identity.Parse(prefix); err == nil {
		t.Fatal("glyph accepted a prefix")
	}
	if _, err := mbox.ParseID(prefix); err == nil {
		t.Fatal("mailbox accepted a prefix")
	}
}

func TestRefusesPublicMailbox(t *testing.T) {
	id := mustID(t)
	store := mustStore(t, id)
	if _, err := Dial("8.8.8.8:80", id, store, nil); !errors.Is(err, mbox.ErrPublicBind) {
		t.Fatalf("public dial err=%v", err)
	}
	if _, err := Dial("0.0.0.0:80", id, store, nil); !errors.Is(err, mbox.ErrPublicBind) {
		t.Fatalf("unspecified dial err=%v", err)
	}
}

func TestDepositPullOpen(t *testing.T) {
	dir, addr, owner, bobID, pin := mailboxWithFriend(t)
	aliceStore := mustStore(t, owner)
	bobStore := mustStore(t, bobID)
	if err := aliceStore.Add(bobID.ID(), "Bob"); err != nil {
		t.Fatal(err)
	}
	if err := bobStore.Add(owner.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	alice := mustDial(t, addr, owner, aliceStore, pin)
	defer alice.Close()
	bob := mustDial(t, addr, bobID, bobStore, pin)
	defer bob.Close()
	const marker = "glyph-secret-marker-hello-9f3a2c"
	if err := alice.Send(bobID.ID(), marker, 5000); err != nil {
		t.Fatal(err)
	}
	if err := alice.Send(bobID.ID(), "second", 1); err != nil {
		t.Fatal(err)
	}
	if err := walkContains(dir, []byte(marker)); err != nil {
		t.Fatal(err)
	}
	if err := bob.Pull(); err != nil {
		t.Fatal(err)
	}
	view, err := bobStore.Conversation(owner.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Messages) != 2 || view.Messages[0].Text != marker || view.Messages[1].Text != "second" {
		t.Fatalf("order %#v", view.Messages)
	}
	if view.Messages[0].Unix != 5000 || view.Messages[1].Unix != 1 || view.Messages[0].Counter != 1 || view.Messages[1].Counter != 2 {
		t.Fatalf("sorted by unix time: %#v", view.Messages)
	}
	if err := bob.Send(owner.ID(), "reply", 1); err != nil {
		t.Fatal(err)
	}
	if err := alice.Pull(); err != nil {
		t.Fatal(err)
	}
	back, err := aliceStore.Conversation(bobID.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Messages) != 3 || back.Messages[2].Text != "reply" {
		t.Fatalf("reply %#v", back.Messages)
	}
}

func TestFailedOpenDoesNotAck(t *testing.T) {
	dir, addr, owner, bobID, pin := mailboxWithFriend(t)
	aliceStore := mustStore(t, owner)
	bobStore := mustStore(t, bobID)
	if err := aliceStore.Add(bobID.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := bobStore.Add(owner.ID(), ""); err != nil {
		t.Fatal(err)
	}
	alice := mustDial(t, addr, owner, aliceStore, pin)
	defer alice.Close()
	bob := mustDial(t, addr, bobID, bobStore, pin)
	defer bob.Close()
	if err := alice.Send(bobID.ID(), "good-letter", 10); err != nil {
		t.Fatal(err)
	}
	raw, err := mbox.Dial(addr, owner.Private(), pin)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	garbage := []byte("this-blob-is-not-a-seal")
	if err := raw.Put(bobID.ID(), garbage); err != nil {
		t.Fatal(err)
	}
	if err := bob.Pull(); err != nil {
		t.Fatal(err)
	}
	view, err := bobStore.Conversation(owner.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Messages) != 1 || view.Messages[0].Text != "good-letter" {
		t.Fatalf("opened %#v", view.Messages)
	}
	left, err := rawList(addr, bobID, pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("failed open stayed on the mailbox: %#v", left)
	}
	_ = dir
}

func TestSuccessorThroughMailbox(t *testing.T) {
	dir, addr, owner, bobID, pin := mailboxWithFriend(t)
	aliceStore := mustStore(t, owner)
	bobStore := mustStore(t, bobID)
	if err := aliceStore.Add(bobID.ID(), "Bob"); err != nil {
		t.Fatal(err)
	}
	if err := bobStore.Add(owner.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	alice := mustDial(t, addr, owner, aliceStore, pin)
	defer alice.Close()
	bob := mustDial(t, addr, bobID, bobStore, pin)
	defer bob.Close()
	if err := alice.Send(bobID.ID(), "kept-history", 100); err != nil {
		t.Fatal(err)
	}
	if err := bob.Pull(); err != nil {
		t.Fatal(err)
	}
	next := mustID(t)
	if err := alice.SendSuccessor(bobID.ID(), next, 1); err != nil {
		t.Fatal(err)
	}
	if err := bob.Pull(); err != nil {
		t.Fatal(err)
	}
	if _, err := bobStore.Conversation(next.ID()); !errors.Is(err, transcript.ErrNotFound) {
		t.Fatal("successor followed before it was accepted")
	}
	if _, err := bobStore.Accept(owner.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := bobStore.Conversation(owner.ID()); !errors.Is(err, transcript.ErrNotFound) {
		t.Fatal("old glyph id still addresses the chat")
	}
	view, err := bobStore.Conversation(next.ID())
	if err != nil {
		t.Fatal(err)
	}
	if view.Name != "Ada" || len(view.Messages) != 2 || view.Messages[0].Text != "kept-history" || view.Messages[1].Kind != seal.KindSuccessor || view.Messages[1].Next != next.ID() {
		t.Fatalf("history %+v", view)
	}
	allow, err := os.ReadFile(filepath.Join(dir, "allowlist"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(allow, []byte(next.ID())) {
		t.Fatal("mailbox learned the successor id")
	}
	if _, err := mbox.Dial(addr, next.Private(), pin); !errors.Is(err, mbox.ErrUnauthorized) {
		t.Fatalf("new id dialed the mailbox: %v", err)
	}
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte("kept-history")) || bytes.Contains(b, []byte(next.ID())) {
			t.Fatalf("mailbox file %s contains letter contents", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConflictingSuccessorDoesNotBrick(t *testing.T) {
	_, addr, alice, bob, pin := mailboxWithFriend(t)
	bobDir := t.TempDir()
	bobStore, err := transcript.Open(bobDir, bob.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := bobStore.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	other := mustID(t)
	if err := bobStore.Add(other.ID(), "Zoe"); err != nil {
		t.Fatal(err)
	}
	if err := bobStore.CommitOutgoing(seal.Message{
		Sender: bob.ID(), Recipient: other.ID(), Kind: seal.KindChat,
		Counter: 1, Unix: 1, Text: "other-chat",
	}); err != nil {
		t.Fatal(err)
	}
	session := mustDial(t, addr, bob, bobStore, pin)
	defer session.Close()
	k1 := mustID(t)
	k2 := mustID(t)
	put := func(msg seal.Message) {
		t.Helper()
		blob, err := seal.Seal(alice.Private(), bob.ID(), msg)
		if err != nil {
			t.Fatal(err)
		}
		box, err := mbox.Dial(addr, alice.Private(), pin)
		if err != nil {
			t.Fatal(err)
		}
		defer box.Close()
		if err := box.Put(bob.ID(), blob); err != nil {
			t.Fatal(err)
		}
	}
	successor := func(next *identity.Identity, n uint64) seal.Message {
		t.Helper()
		sig, err := seal.SignSuccessor(next.Private(), alice.ID(), bob.ID(), next.ID())
		if err != nil {
			t.Fatal(err)
		}
		return seal.Message{
			Kind: seal.KindSuccessor, Counter: n, Unix: 1, Next: next.ID(), NextSig: sig,
		}
	}
	put(successor(k1, 1))
	if err := session.Pull(); err != nil {
		t.Fatal(err)
	}
	put(successor(k2, 3))
	if err := session.Pull(); err != nil {
		t.Fatal(err)
	}
	put(seal.Message{Kind: seal.KindChat, Counter: 2, Unix: 1, Text: "real-letter"})
	if err := session.Pull(); err != nil {
		t.Fatal(err)
	}
	view, err := bobStore.Conversation(alice.ID())
	if err != nil {
		t.Fatal(err)
	}
	if view.Pending != k1.ID() || len(view.Messages) != 2 || view.Messages[1].Text != "real-letter" {
		t.Fatalf("gap letter %+v", view)
	}
	put(seal.Message{Kind: seal.KindChat, Counter: 4, Unix: 1, Text: "continues"})
	if err := session.Pull(); err != nil {
		t.Fatal(err)
	}
	reopened, err := transcript.Open(bobDir, bob.ID())
	if err != nil {
		t.Fatal(err)
	}
	aliceView, err := reopened.Conversation(alice.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(aliceView.Messages) != 3 || aliceView.Messages[2].Text != "continues" {
		t.Fatalf("reopened %+v", aliceView.Messages)
	}
	zoeView, err := reopened.Conversation(other.ID())
	if err != nil || len(zoeView.Messages) != 1 || zoeView.Messages[0].Text != "other-chat" {
		t.Fatalf("other chat %+v %v", zoeView, err)
	}
}

func TestLetterArrivesBeforeChat(t *testing.T) {
	_, addr, alice, bob, pin := mailboxWithFriend(t)
	aliceStore := mustStore(t, alice)
	bobStore := mustStore(t, bob)
	if err := aliceStore.Add(bob.ID(), "Bob"); err != nil {
		t.Fatal(err)
	}
	aliceC := mustDial(t, addr, alice, aliceStore, pin)
	defer aliceC.Close()
	bobC := mustDial(t, addr, bob, bobStore, pin)
	defer bobC.Close()
	if err := aliceC.Send(bob.ID(), "hello-before-add", 10); err != nil {
		t.Fatal(err)
	}
	if err := bobC.Pull(); err != nil {
		t.Fatal(err)
	}
	left, err := rawList(addr, bob, pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Fatalf("letter dropped before the chat existed: %#v", left)
	}
	if err := bobStore.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := bobC.Pull(); err != nil {
		t.Fatal(err)
	}
	view, err := bobStore.Conversation(alice.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Messages) != 1 || view.Messages[0].Text != "hello-before-add" {
		t.Fatalf("opened %#v", view.Messages)
	}
	left, err = rawList(addr, bob, pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("letter stayed after the chat existed: %#v", left)
	}
}

func TestNewKeyLetterWaitsForAccept(t *testing.T) {
	_, addr, alice, bob, pin := mailboxWithFriend(t)
	aliceStore := mustStore(t, alice)
	bobStore := mustStore(t, bob)
	if err := aliceStore.Add(bob.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := bobStore.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	aliceC := mustDial(t, addr, alice, aliceStore, pin)
	defer aliceC.Close()
	bobC := mustDial(t, addr, bob, bobStore, pin)
	defer bobC.Close()
	next := mustID(t)
	if err := aliceC.SendSuccessor(bob.ID(), next, 1); err != nil {
		t.Fatal(err)
	}
	if err := bobC.Pull(); err != nil {
		t.Fatal(err)
	}
	if err := aliceC.Introduce(next.ID()); err != nil {
		t.Fatal(err)
	}
	blob, err := seal.Seal(next.Private(), bob.ID(), seal.Message{
		Kind: seal.KindChat, Counter: 1, Unix: 2, Text: "from-new-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	box, err := mbox.Dial(addr, next.Private(), pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := box.Put(bob.ID(), blob); err != nil {
		box.Close()
		t.Fatal(err)
	}
	box.Close()
	if err := bobC.Pull(); err != nil {
		t.Fatal(err)
	}
	if _, err := bobStore.Conversation(next.ID()); !errors.Is(err, transcript.ErrNotFound) {
		t.Fatal("followed the new id before accept")
	}
	left, err := rawList(addr, bob, pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Fatalf("early letter dropped: %#v", left)
	}
	if _, err := bobStore.Accept(alice.ID()); err != nil {
		t.Fatal(err)
	}
	if err := bobC.Pull(); err != nil {
		t.Fatal(err)
	}
	view, err := bobStore.Conversation(next.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Messages) != 2 || view.Messages[1].Text != "from-new-key" {
		t.Fatalf("new key letter %+v", view.Messages)
	}
	left, err = rawList(addr, bob, pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("letter stayed after accept: %#v", left)
	}
}

func mailboxWithFriend(t *testing.T) (dir, addr string, owner, friend *identity.Identity, pin ed25519.PublicKey) {
	t.Helper()
	owner = mustID(t)
	friend = mustID(t)
	dir = t.TempDir()
	srv, err := mbox.New(dir, owner.ID())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	pin = srv.Pin()
	addr, err = srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := mbox.Dial(addr, owner.Private(), pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Introduce(friend.ID()); err != nil {
		c.Close()
		t.Fatal(err)
	}
	c.Close()
	return dir, addr, owner, friend, pin
}

func mustID(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustStore(t *testing.T, id *identity.Identity) *transcript.Store {
	t.Helper()
	s, err := transcript.Open(t.TempDir(), id.ID())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustDial(t *testing.T, addr string, id *identity.Identity, store *transcript.Store, pin ed25519.PublicKey) *Client {
	t.Helper()
	c, err := Dial(addr, id, store, pin)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func rawList(addr string, id *identity.Identity, pin ed25519.PublicKey) ([]mbox.Letter, error) {
	c, err := mbox.Dial(addr, id.Private(), pin)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.List()
}

func walkContains(root string, needle []byte) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, needle) {
			return errors.New("plaintext found in " + path)
		}
		return nil
	})
}
