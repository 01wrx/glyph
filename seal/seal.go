// Package seal signs a glyph letter and encrypts it to the recipient's glyph
// ID. The mailbox and the network see ciphertext only.
package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf8"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"glyph/identity"
)

const (
	version = 1
	// version || sender || recipient || ephemeral || nonce
	headerLen = 1 + 32 + 32 + 32 + 12
	maxText   = 48 * 1024
)

var (
	// ErrBadSignature means the sender's signature does not verify.
	ErrBadSignature = errors.New("seal: bad signature")
	// ErrRecipient means the letter is not sealed to this key.
	ErrRecipient = errors.New("seal: recipient mismatch")
	// ErrTruncated means the blob is short or its ciphertext does not authenticate.
	ErrTruncated = errors.New("seal: truncated blob")
	// ErrInvalid means the letter is not a well-formed glyph seal.
	ErrInvalid = errors.New("seal: invalid")
)

// Kind is the payload type inside a seal.
type Kind uint8

const (
	KindChat      Kind = 1
	KindSuccessor Kind = 2
)

// Message is a letter after it has been opened. Unix is display-only.
// Counter is the sender's sequence number in this conversation.
// Next is set only for a successor, and it is a full glyph ID.
type Message struct {
	Sender    string
	Recipient string
	Kind      Kind
	Counter   uint64
	Unix      int64
	Text      string
	Next      string
	// NextSig is the next key's signature over the sender, the next key, and
	// the recipient. It is required for a successor and is inside the ciphertext.
	NextSig []byte
}

// Seal signs msg with sender and encrypts it to recipientID.
// Sender and recipient are bound into the signature and the authenticated data.
// The returned blob does not contain the plaintext.
func Seal(sender ed25519.PrivateKey, recipientID string, msg Message) ([]byte, error) {
	if len(sender) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	recipient, err := identity.Parse(recipientID)
	if err != nil {
		return nil, err
	}
	senderPub, err := identity.ParsePublic(sender.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if msg.Kind == KindSuccessor {
		next, err := identity.Parse(msg.Next)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(next, senderPub) || bytes.Equal(next, recipient) {
			return nil, ErrInvalid
		}
		if err := verifySuccessor(senderPub, recipient, next, msg.NextSig); err != nil {
			return nil, err
		}
	}
	payload, err := encodePayload(msg)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(sender, sigInput(senderPub, recipient, payload))
	return encryptSigned(senderPub, recipient, sig, payload)
}

// Open decrypts blob with the recipient's key, checks that the letter is
// addressed to that key, and verifies the sender's signature.
// A bad signature, a swapped recipient, or a truncated blob is rejected.
// Replay is rejected by the transcript, which remembers counters.
func Open(recipient ed25519.PrivateKey, blob []byte) (Message, error) {
	if len(recipient) != ed25519.PrivateKeySize {
		return Message{}, ErrInvalid
	}
	ourPub, err := identity.ParsePublic(recipient.Public().(ed25519.PublicKey))
	if err != nil {
		return Message{}, ErrInvalid
	}
	if len(blob) < headerLen+ed25519.SignatureSize+chacha20poly1305.Overhead+1 {
		return Message{}, ErrTruncated
	}
	if blob[0] != version {
		return Message{}, ErrInvalid
	}
	sender := make([]byte, 32)
	recip := make([]byte, 32)
	eph := make([]byte, 32)
	nonce := make([]byte, 12)
	copy(sender, blob[1:33])
	copy(recip, blob[33:65])
	copy(eph, blob[65:97])
	copy(nonce, blob[97:109])
	ct := append([]byte(nil), blob[109:]...)
	if !bytes.Equal(recip, ourPub) {
		return Message{}, ErrRecipient
	}
	if _, err := identity.ParsePublic(sender); err != nil {
		return Message{}, ErrInvalid
	}
	xPriv, err := edPrivToX(recipient)
	if err != nil {
		return Message{}, ErrInvalid
	}
	ephKey, err := ecdh.X25519().NewPublicKey(eph)
	if err != nil {
		return Message{}, ErrTruncated
	}
	shared, err := xPriv.ECDH(ephKey)
	if err != nil {
		return Message{}, ErrTruncated
	}
	defer clear(shared)
	key, err := deriveKey(shared, eph, sender, recip)
	if err != nil {
		return Message{}, ErrInvalid
	}
	defer clear(key)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return Message{}, ErrInvalid
	}
	plain, err := aead.Open(nil, nonce, ct, aad(sender, recip))
	if err != nil {
		return Message{}, ErrTruncated
	}
	if len(plain) < ed25519.SignatureSize+1 {
		return Message{}, ErrTruncated
	}
	sig := plain[:ed25519.SignatureSize]
	payload := plain[ed25519.SignatureSize:]
	if !ed25519.Verify(sender, sigInput(sender, recip, payload), sig) {
		return Message{}, ErrBadSignature
	}
	msg, err := parsePayload(payload)
	if err != nil {
		return Message{}, err
	}
	msg.Sender, err = identity.Format(sender)
	if err != nil {
		return Message{}, ErrInvalid
	}
	msg.Recipient, err = identity.Format(recip)
	if err != nil {
		return Message{}, ErrInvalid
	}
	if msg.Kind == KindSuccessor {
		next, err := identity.Parse(msg.Next)
		if err != nil {
			return Message{}, ErrInvalid
		}
		if err := verifySuccessor(ed25519.PublicKey(sender), ed25519.PublicKey(recip), next, msg.NextSig); err != nil {
			return Message{}, err
		}
	}
	return msg, nil
}

// SignSuccessor proves the next key consents to replace sender for recipient.
func SignSuccessor(next ed25519.PrivateKey, senderID, recipientID, nextID string) ([]byte, error) {
	if len(next) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	sender, err := identity.Parse(senderID)
	if err != nil {
		return nil, err
	}
	recip, err := identity.Parse(recipientID)
	if err != nil {
		return nil, err
	}
	pub, err := identity.Parse(nextID)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(next.Public().(ed25519.PublicKey), pub) {
		return nil, ErrInvalid
	}
	return ed25519.Sign(next, successorSignBytes(sender, pub, recip)), nil
}

// VerifySuccessor checks the next key's signature inside a successor letter.
func VerifySuccessor(senderID, recipientID, nextID string, sig []byte) error {
	sender, err := identity.Parse(senderID)
	if err != nil {
		return ErrBadSignature
	}
	recip, err := identity.Parse(recipientID)
	if err != nil {
		return ErrBadSignature
	}
	next, err := identity.Parse(nextID)
	if err != nil {
		return ErrBadSignature
	}
	return verifySuccessor(sender, recip, next, sig)
}

func verifySuccessor(sender, recipient, next ed25519.PublicKey, sig []byte) error {
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(next, successorSignBytes(sender, next, recipient), sig) {
		return ErrBadSignature
	}
	return nil
}

func successorSignBytes(sender, next, recipient []byte) []byte {
	var b bytes.Buffer
	b.WriteString("glyph-successor-v1")
	b.WriteByte(0)
	b.Write(sender)
	b.Write(next)
	b.Write(recipient)
	return b.Bytes()
}

func encryptSigned(senderPub, recipientPub ed25519.PublicKey, sig, payload []byte) ([]byte, error) {
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrBadSignature
	}
	if _, err := identity.ParsePublic(senderPub); err != nil {
		return nil, err
	}
	if _, err := identity.ParsePublic(recipientPub); err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	recipX, err := edPubToX(recipientPub)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(recipX)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(shared)
	ephPub := eph.PublicKey().Bytes()
	key, err := deriveKey(shared, ephPub, senderPub, recipientPub)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := chacha20poly1305.New(key)
	if err != nil || aead.NonceSize() != 12 {
		return nil, ErrInvalid
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	plain := make([]byte, 0, len(sig)+len(payload))
	plain = append(plain, sig...)
	plain = append(plain, payload...)
	ct := aead.Seal(nil, nonce, plain, aad(senderPub, recipientPub))
	out := make([]byte, 0, headerLen+len(ct))
	out = append(out, version)
	out = append(out, senderPub...)
	out = append(out, recipientPub...)
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func sigInput(sender, recipient, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("glyph-seal-v1")
	b.WriteByte(0)
	b.Write(sender)
	b.Write(recipient)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(payload)))
	b.Write(n[:])
	b.Write(payload)
	return b.Bytes()
}

func aad(sender, recipient []byte) []byte {
	var b bytes.Buffer
	b.WriteString("glyph-seal-aad-v1")
	b.WriteByte(0)
	b.Write(sender)
	b.Write(recipient)
	return b.Bytes()
}

func deriveKey(shared, ephPub, sender, recipient []byte) ([]byte, error) {
	info := make([]byte, 0, 13+64)
	info = append(info, "glyph-seal-v1"...)
	info = append(info, sender...)
	info = append(info, recipient...)
	r := hkdf.New(sha256.New, shared, ephPub, info)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func edPubToX(pub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	if _, err := identity.ParsePublic(pub); err != nil {
		return nil, err
	}
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(p.BytesMontgomery())
}

func edPrivToX(priv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	seed := priv.Seed()
	defer clear(seed)
	sum := sha512.Sum512(seed)
	defer clear(sum[:])
	return ecdh.X25519().NewPrivateKey(sum[:32])
}

func encodePayload(msg Message) ([]byte, error) {
	if msg.Counter == 0 || msg.Counter > 1<<32 {
		return nil, ErrInvalid
	}
	var b bytes.Buffer
	switch msg.Kind {
	case KindChat:
		if msg.Next != "" || !utf8.ValidString(msg.Text) || len(msg.Text) > maxText {
			return nil, ErrInvalid
		}
		b.WriteByte(byte(KindChat))
		writeU64(&b, msg.Counter)
		writeU64(&b, uint64(msg.Unix))
		writeU32(&b, uint32(len(msg.Text)))
		b.WriteString(msg.Text)
	case KindSuccessor:
		if msg.Text != "" {
			return nil, ErrInvalid
		}
		next, err := identity.Parse(msg.Next)
		if err != nil {
			return nil, err
		}
		if len(msg.NextSig) != ed25519.SignatureSize {
			return nil, ErrInvalid
		}
		b.WriteByte(byte(KindSuccessor))
		writeU64(&b, msg.Counter)
		writeU64(&b, uint64(msg.Unix))
		b.Write(next)
		b.Write(msg.NextSig)
	default:
		return nil, ErrInvalid
	}
	return b.Bytes(), nil
}

func parsePayload(p []byte) (Message, error) {
	if len(p) < 1+8+8 {
		return Message{}, ErrTruncated
	}
	kind := Kind(p[0])
	counter := binary.BigEndian.Uint64(p[1:9])
	unix := int64(binary.BigEndian.Uint64(p[9:17]))
	if counter == 0 || counter > 1<<32 {
		return Message{}, ErrInvalid
	}
	rest := p[17:]
	switch kind {
	case KindChat:
		if len(rest) < 4 {
			return Message{}, ErrTruncated
		}
		n := binary.BigEndian.Uint32(rest[:4])
		body := rest[4:]
		if uint32(len(body)) < n {
			return Message{}, ErrTruncated
		}
		if uint32(len(body)) != n || n > maxText {
			return Message{}, ErrInvalid
		}
		text := string(body)
		if !utf8.ValidString(text) {
			return Message{}, ErrInvalid
		}
		return Message{Kind: KindChat, Counter: counter, Unix: unix, Text: text}, nil
	case KindSuccessor:
		if len(rest) < 32+ed25519.SignatureSize {
			return Message{}, ErrTruncated
		}
		if len(rest) != 32+ed25519.SignatureSize {
			return Message{}, ErrInvalid
		}
		next, err := identity.Format(rest[:32])
		if err != nil {
			return Message{}, ErrInvalid
		}
		sig := append([]byte(nil), rest[32:]...)
		return Message{Kind: KindSuccessor, Counter: counter, Unix: unix, Next: next, NextSig: sig}, nil
	default:
		return Message{}, ErrInvalid
	}
}

func writeU64(b *bytes.Buffer, v uint64) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	b.Write(n[:])
}

func writeU32(b *bytes.Buffer, v uint32) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], v)
	b.Write(n[:])
}
