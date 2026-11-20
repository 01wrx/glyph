package discover

import (
	"bytes"
	"testing"
)

func TestBencodeRoundTrip(t *testing.T) {
	msg := map[string]any{
		"t": "aa",
		"y": "q",
		"q": "ping",
		"a": map[string]any{"id": string(bytes.Repeat([]byte{'a'}, 20))},
	}
	raw, err := marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	want := "d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:aa1:y1:qe"
	if string(raw) != want {
		t.Fatalf("encode %q", raw)
	}
	back, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := back.(map[string]any)
	if got["q"] != "ping" || got["a"].(map[string]any)["id"] != string(bytes.Repeat([]byte{'a'}, 20)) {
		t.Fatalf("decode %#v", got)
	}
	if _, err := unmarshal([]byte("di1e1:ae")); err == nil {
		t.Fatal("unsorted or bad dict accepted")
	}
	if _, err := unmarshal([]byte("i-0e")); err == nil {
		t.Fatal("negative zero accepted")
	}
}
