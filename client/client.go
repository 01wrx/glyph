// Package client hands sealed letters to a glyph mailbox and opens the
// letters that mailbox returns for this glyph ID.
package client

import (
	"crypto/ed25519"
	"errors"

	"glyph/identity"
	"glyph/seal"
	"glyph/transcript"

	mbox "glyph-mailbox"
)

// Client is one glyph ID's session with a mailbox on a LAN address.
type Client struct {
	id    *identity.Identity
	store *transcript.Store
	box   *mbox.Client
}

// Dial authenticates to the mailbox at addr. addr must be a private LAN
// address or loopback. pin is the mailbox public key. The store must belong to id.
func Dial(addr string, id *identity.Identity, store *transcript.Store, pin ed25519.PublicKey) (*Client, error) {
	if id == nil || store == nil || id.ID() == "" || store.Self() != id.ID() {
		return nil, errors.New("glyph: identity does not match store")
	}
	if err := mbox.ValidateAddr(addr); err != nil {
		return nil, err
	}
	box, err := mbox.Dial(addr, id.Private(), pin)
	if err != nil {
		return nil, err
	}
	return &Client{id: id, store: store, box: box}, nil
}

// Close closes the mailbox connection.
func (c *Client) Close() error {
	if c == nil || c.box == nil {
		return nil
	}
	return c.box.Close()
}

// Introduce asks the mailbox to allow a friend. Only the owner succeeds.
// friend must be a full canonical glyph ID.
func (c *Client) Introduce(friend string) error {
	if _, err := identity.Parse(friend); err != nil {
		return err
	}
	return c.box.Introduce(friend)
}

// Remove asks the mailbox to drop a friend and that friend's inbound lane.
// Only the owner succeeds, and the owner cannot remove their own id.
func (c *Client) Remove(friend string) error {
	if _, err := identity.Parse(friend); err != nil {
		return err
	}
	return c.box.Remove(friend)
}

// Send seals text to peer and deposits the ciphertext. The counter is the
// next counter for this sender in that conversation. unix is stored for
// display and is not the order.
func (c *Client) Send(peer, text string, unix int64) error {
	if _, err := identity.Parse(peer); err != nil {
		return err
	}
	n, err := c.store.NextCounter(peer)
	if err != nil {
		return err
	}
	blob, err := seal.Seal(c.id.Private(), peer, seal.Message{
		Kind: seal.KindChat, Counter: n, Unix: unix, Text: text,
	})
	if err != nil {
		return err
	}
	if err := c.box.Put(peer, blob); err != nil {
		return err
	}
	return c.store.CommitOutgoing(seal.Message{
		Sender: c.id.ID(), Recipient: peer, Kind: seal.KindChat,
		Counter: n, Unix: unix, Text: text,
	})
}

// SendSuccessor seals "my next glyph ID is next" to the current peer.
// The sender's own store stays keyed by the peer. The peer's store follows
// next only after they accept this letter.
func (c *Client) SendSuccessor(peer string, next *identity.Identity, unix int64) error {
	if next == nil || next.ID() == "" {
		return transcript.ErrSuccessor
	}
	if _, err := identity.Parse(peer); err != nil {
		return err
	}
	n, err := c.store.NextCounter(peer)
	if err != nil {
		return err
	}
	sig, err := seal.SignSuccessor(next.Private(), c.id.ID(), peer, next.ID())
	if err != nil {
		return err
	}
	blob, err := seal.Seal(c.id.Private(), peer, seal.Message{
		Kind: seal.KindSuccessor, Counter: n, Unix: unix, Next: next.ID(), NextSig: sig,
	})
	if err != nil {
		return err
	}
	if err := c.box.Put(peer, blob); err != nil {
		return err
	}
	return c.store.CommitOutgoing(seal.Message{
		Sender: c.id.ID(), Recipient: peer, Kind: seal.KindSuccessor,
		Counter: n, Unix: unix, Next: next.ID(),
	})
}

// Pull walks each page of this ID's blobs. An opened letter is acknowledged,
// including a duplicate counter. A blob that cannot open, a letter for
// someone else, or a permanent reject of the peer's next counter is dropped.
// A letter from a glyph ID that is not a chat yet stays on the mailbox until
// that chat exists. A later counter that the transcript is not ready for
// stays on the mailbox.
func (c *Client) Pull() error {
	after := ""
	for {
		letters, more, err := c.box.ListAfter(after)
		if err != nil {
			return err
		}
		if len(letters) == 0 {
			return nil
		}
		var ack, drop []string
		for _, lt := range letters {
			after = lt.ID
			msg, err := seal.Open(c.id.Private(), lt.Blob)
			if err != nil {
				drop = append(drop, lt.ID)
				continue
			}
			err = c.store.Ingest(msg)
			switch {
			case err == nil || errors.Is(err, transcript.ErrReplay):
				ack = append(ack, lt.ID)
			case errors.Is(err, transcript.ErrStranger):
				// The sender is not a chat yet. The letter stays so it can be
				// read after that glyph ID is added.
			case errors.Is(err, transcript.ErrRecipient):
				drop = append(drop, lt.ID)
			case errors.Is(err, transcript.ErrSuccessor) || errors.Is(err, transcript.ErrInvalid):
				if skipErr := c.store.Skip(msg); skipErr == nil {
					drop = append(drop, lt.ID)
				}
			}
		}
		if len(ack) > 0 {
			if err := c.box.Ack(ack); err != nil {
				return err
			}
		}
		if len(drop) > 0 {
			if err := c.box.Drop(drop); err != nil {
				return err
			}
		}
		if !more {
			return nil
		}
	}
}
