package client

import (
	"crypto/ed25519"
	"errors"

	"glyph/identity"
	"glyph/transcript"

	mbox "glyph-mailbox"
)

// State is the mailbox the window shows.
// Unset means the settings section offers setup and the bottom light is absent.
// Online means the bottom light is green and that settings section is absent.
// The two are mutually exclusive.
type State int

const (
	StateUnset State = iota
	StateOnline
)

// ErrStale means a mailbox answered, and it does not speak this app's protocol.
var ErrStale = errors.New("glyph: mailbox is not current")

// Attach dials addr and pulls waiting letters.
// A mailbox is set up only while it is online and speaks the current protocol.
// A closed mailbox, a public address, or an older protocol stays unset.
func Attach(addr string, id *identity.Identity, store *transcript.Store, pin ed25519.PublicKey) (*Client, State, error) {
	c, err := Dial(addr, id, store, pin)
	if err != nil {
		if errors.Is(err, mbox.ErrProtocol) {
			return nil, StateUnset, ErrStale
		}
		return nil, StateUnset, err
	}
	if err := c.Pull(); err != nil {
		c.Close()
		return nil, StateUnset, err
	}
	return c, StateOnline, nil
}
