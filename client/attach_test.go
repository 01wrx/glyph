package client

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"testing"

	mbox "glyph-mailbox"
)

func TestAttachOnlineWhenMailboxIsCurrent(t *testing.T) {
	_, addr, owner, _, pin := mailboxWithFriend(t)
	store := mustStore(t, owner)
	c, state, err := Attach(addr, owner, store, pin)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if state != StateOnline {
		t.Fatalf("state %v", state)
	}
}

func TestAttachUnsetWhenMailboxIsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	id := mustID(t)
	c, state, err := Attach(addr, id, mustStore(t, id), id.Public())
	if c != nil {
		c.Close()
		t.Fatal("closed mailbox returned a client")
	}
	if state != StateUnset || err == nil {
		t.Fatalf("state %v err %v", state, err)
	}
}

func TestAttachUnsetWhenMailboxIsStale(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return
		}
		raw, err := json.Marshal(map[string]any{"v": mbox.Protocol() + 1, "type": "hello", "nonce": nonce})
		if err != nil {
			return
		}
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))
		_, _ = c.Write(hdr[:])
		_, _ = c.Write(raw)
	}()
	id := mustID(t)
	c, state, err := Attach(ln.Addr().String(), id, mustStore(t, id), id.Public())
	if c != nil {
		c.Close()
		t.Fatal("stale mailbox returned a client")
	}
	if state != StateUnset || !errors.Is(err, ErrStale) {
		t.Fatalf("state %v err %v", state, err)
	}
}
