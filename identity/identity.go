// Package identity is a static Ed25519 glyph ID. The ID is the public key.
// It is not registered anywhere, and a short prefix of it is not an address.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"

	"filippo.io/edwards25519"
)

const prefix = "glyph:"

var (
	// ErrInvalidID means the text is not one full canonical glyph ID.
	ErrInvalidID = errors.New("identity: invalid glyph id")
	// ErrKeyFile means the key file is missing or not this package's format.
	ErrKeyFile = errors.New("identity: invalid key file")
)

// Identity is the private key for one glyph ID.
type Identity struct {
	priv ed25519.PrivateKey
}

// Generate creates a new key. The glyph ID is the canonical encoding of the
// public half. Nothing is written until Save.
func Generate() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := &Identity{priv: priv}
	if _, err := Parse(id.ID()); err != nil {
		return nil, err
	}
	return id, nil
}

// ID is the canonical glyph ID. It is empty only if the key is unusable.
func (id *Identity) ID() string {
	if id == nil {
		return ""
	}
	s, err := Format(id.Public())
	if err != nil {
		return ""
	}
	return s
}

// Public returns a copy of the Ed25519 public key.
func (id *Identity) Public() ed25519.PublicKey {
	if id == nil || len(id.priv) != ed25519.PrivateKeySize {
		return nil
	}
	pub := id.priv.Public().(ed25519.PublicKey)
	out := make(ed25519.PublicKey, len(pub))
	copy(out, pub)
	return out
}

// Private returns a copy of the Ed25519 private key for sealing and for
// proving this ID to a mailbox. The mailbox never receives this key.
func (id *Identity) Private() ed25519.PrivateKey {
	if id == nil || len(id.priv) != ed25519.PrivateKeySize {
		return nil
	}
	out := make(ed25519.PrivateKey, len(id.priv))
	copy(out, id.priv)
	return out
}

// Save writes the seed to path. It refuses to replace an existing file.
func (id *Identity) Save(path string) error {
	if id == nil || len(id.priv) != ed25519.PrivateKeySize {
		return ErrKeyFile
	}
	seed := id.priv.Seed()
	var buf bytes.Buffer
	buf.WriteString("glyph-key-v1\n")
	buf.WriteString(hex.EncodeToString(seed))
	buf.WriteByte('\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Load reads a key file written by Save.
func Load(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.HasSuffix(b, []byte("\r\n")) || bytes.Contains(b, []byte("\r")) {
		return nil, ErrKeyFile
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	lines := bytes.Split(b, []byte("\n"))
	if len(lines) != 2 || string(lines[0]) != "glyph-key-v1" {
		return nil, ErrKeyFile
	}
	h := string(lines[1])
	if len(h) != hex.EncodedLen(ed25519.SeedSize) || !lowerHex(h) {
		return nil, ErrKeyFile
	}
	seed, err := hex.DecodeString(h)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrKeyFile
	}
	priv := ed25519.NewKeyFromSeed(seed)
	id := &Identity{priv: priv}
	if _, err := Parse(id.ID()); err != nil {
		return nil, ErrKeyFile
	}
	return id, nil
}

// Parse accepts only a full canonical glyph ID. Prefixes, uppercase hex,
// extra characters, and non-canonical or small-order points are rejected.
func Parse(s string) (ed25519.PublicKey, error) {
	if len(s) != len(prefix)+hex.EncodedLen(ed25519.PublicKeySize) {
		return nil, ErrInvalidID
	}
	if s[:len(prefix)] != prefix {
		return nil, ErrInvalidID
	}
	h := s[len(prefix):]
	if !lowerHex(h) {
		return nil, ErrInvalidID
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, ErrInvalidID
	}
	return ParsePublic(raw)
}

// ParsePublic checks a raw Ed25519 public key and returns a copy.
func ParsePublic(raw []byte) (ed25519.PublicKey, error) {
	if err := validatePoint(raw); err != nil {
		return nil, ErrInvalidID
	}
	out := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(out, raw)
	return out, nil
}

// Format returns the canonical glyph ID of a public key.
func Format(pub ed25519.PublicKey) (string, error) {
	p, err := ParsePublic(pub)
	if err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(p), nil
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validatePoint(raw []byte) error {
	if len(raw) != ed25519.PublicKeySize {
		return ErrInvalidID
	}
	p, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		return ErrInvalidID
	}
	if !bytes.Equal(p.Bytes(), raw) {
		return ErrInvalidID
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return ErrInvalidID
	}
	return nil
}
