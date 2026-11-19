package identity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalID(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	id := a.ID()
	if len(id) != len(prefix)+64 || !strings.HasPrefix(id, prefix) {
		t.Fatalf("id %q is not a full canonical glyph id", id)
	}
	if id == b.ID() {
		t.Fatal("two generated ids matched")
	}
	pub, err := Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, a.Public()) {
		t.Fatal("parsed key != public key")
	}
	again, err := Format(pub)
	if err != nil || again != id {
		t.Fatalf("format roundtrip %q err=%v", again, err)
	}
	if strings.Contains(id, hex.EncodeToString(a.Private().Seed())) {
		t.Fatal("glyph id contains the secret seed")
	}
	if _, err := Parse(id[:len(id)-1]); err == nil {
		t.Fatal("short prefix was accepted as an address")
	}
}

func TestParseAcceptsOnlyFullCanonicalID(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	full := id.ID()
	hexPart := strings.TrimPrefix(full, prefix)
	rejects := []string{
		"",
		prefix,
		"glyph",
		full[:20],
		full[:len(full)-1],
		full + "a",
		hexPart,
		"GLYPH:" + hexPart,
		"glyph:" + strings.ToUpper(hexPart),
		" " + full,
		full + "\n",
		"glyph:" + hexPart[:63] + "g",
	}
	for _, s := range rejects {
		if _, err := Parse(s); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("Parse(%q) err=%v, want invalid id", s, err)
		}
	}
	ident := make([]byte, 32)
	ident[0] = 1
	if _, err := Parse(prefix + hex.EncodeToString(ident)); !errors.Is(err, ErrInvalidID) {
		t.Fatal("identity point accepted")
	}
	ident[31] = 0x80
	if _, err := Parse(prefix + hex.EncodeToString(ident)); !errors.Is(err, ErrInvalidID) {
		t.Fatal("non-canonical point accepted")
	}
	if _, err := Parse(full); err != nil {
		t.Fatal(err)
	}
}

func TestKeyFile(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "glyph.key")
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := id.Save(path); err == nil {
		t.Fatal("Save replaced an existing key")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(id.ID())) {
		t.Fatal("key file contains the glyph id")
	}
	if !bytes.HasPrefix(raw, []byte("glyph-key-v1\n")) {
		t.Fatalf("key file %q", raw)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID() != id.ID() {
		t.Fatal("loaded id differs")
	}
	if !bytes.Equal(loaded.Private().Seed(), id.Private().Seed()) {
		t.Fatal("loaded seed differs")
	}
	bad := [][]byte{
		[]byte("glyph-key-v1\n"),
		[]byte("nope\n" + strings.Repeat("ab", 32) + "\n"),
		[]byte("glyph-key-v1\n" + strings.ToUpper(hex.EncodeToString(id.Private().Seed())) + "\n"),
		[]byte("glyph-key-v1\n" + hex.EncodeToString(id.Private().Seed())[:63] + "\n"),
		append(append([]byte{}, raw...), '\n'),
	}
	for _, b := range bad {
		p := filepath.Join(t.TempDir(), "bad.key")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); !errors.Is(err, ErrKeyFile) {
			t.Fatalf("Load bad file err=%v", err)
		}
	}
}
