package discover

import (
	"crypto/ed25519"
	"encoding/binary"
	"time"

	"glyph/identity"
)

const (
	kindPunch  = 1
	kindLetter = 2
	kindAck    = 3

	fragData      = 512
	maxFrags      = 192
	maxBlob       = 96 * 1024
	maxAssemblies = 2
)

func encodeSigned(priv ed25519.PrivateKey, kind byte, body []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize || len(body) > 65535 {
		return nil, errNoPath
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errNoPath
	}
	buf := make([]byte, 5+len(body)+ed25519.SignatureSize)
	buf[0] = 'G'
	buf[1] = 2
	buf[2] = kind
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(body)))
	copy(buf[5:], body)
	sig := ed25519.Sign(priv, buf[:5+len(body)])
	copy(buf[5+len(body):], sig)
	return buf, nil
}

// openSigned verifies pkt against keys this machine already accepted.
// The signer is not written in the packet.
func openSigned(pkt []byte, keys []ed25519.PublicKey) (ed25519.PublicKey, byte, []byte, bool) {
	if len(pkt) < 5+ed25519.SignatureSize || pkt[0] != 'G' || pkt[1] != 2 || len(keys) == 0 {
		return nil, 0, nil, false
	}
	n := int(binary.BigEndian.Uint16(pkt[3:5]))
	if 5+n+ed25519.SignatureSize != len(pkt) {
		return nil, 0, nil, false
	}
	signed := pkt[:5+n]
	sig := pkt[5+n:]
	for _, key := range keys {
		pub, err := identity.ParsePublic(key)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, signed, sig) {
			body := append([]byte(nil), pkt[5:5+n]...)
			return pub, pkt[2], body, true
		}
	}
	return nil, 0, nil, false
}

func letterBody(token []byte, idx, count int, data []byte) []byte {
	b := make([]byte, 18+len(data))
	copy(b[:16], token)
	b[16] = byte(idx)
	b[17] = byte(count)
	copy(b[18:], data)
	return b
}

func splitBlob(blob []byte) [][]byte {
	if len(blob) == 0 || len(blob) > maxBlob {
		return nil
	}
	var out [][]byte
	for len(blob) > 0 {
		n := fragData
		if n > len(blob) {
			n = len(blob)
		}
		out = append(out, blob[:n])
		blob = blob[n:]
	}
	if len(out) > maxFrags {
		return nil
	}
	return out
}

func punchBody(now time.Time) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(now.UnixMilli()))
	return b[:]
}
