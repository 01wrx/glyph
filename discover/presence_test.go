package discover

import (
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"glyph/identity"
)

func TestBEP44Vector(t *testing.T) {
	pub, err := hex.DecodeString("77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString("305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01")
	if err != nil {
		t.Fatal(err)
	}
	msg := presenceMsg("Hello World!", 1)
	if string(msg) != "3:seqi1e1:v12:Hello World!" {
		t.Fatalf("buffer %q", msg)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatal("vector signature")
	}
	sum := sha1.Sum(pub)
	if hex.EncodeToString(sum[:]) != "4a533d47ec9c7d95b1ad75f576cffc641853b750" {
		t.Fatalf("target %x", sum)
	}
}

func TestAddressPolicy(t *testing.T) {
	if !addrOK("8.8.8.8:7421", false) || !addrOK("1.1.1.1:1", false) {
		t.Fatal("public address rejected")
	}
	for _, bad := range []string{"192.168.1.1:7421", "10.1.1.1:1", "127.0.0.1:9", "169.254.169.254:80", "0.0.0.0:1", "224.0.0.1:1", "example.com:1", "8.8.8.8", ""} {
		if addrOK(bad, false) {
			t.Fatalf("accepted %q", bad)
		}
	}
	if !addrOK("127.0.0.1:9", true) || !addrOK("192.168.0.2:7421", true) {
		t.Fatal("local test address rejected")
	}
	if !lanOK("192.168.1.9:7421") || !lanOK("127.0.0.1:9") {
		t.Fatal("private beacon rejected")
	}
	if lanOK("8.8.8.8:7421") || lanOK("0.0.0.0:1") || lanOK("224.0.0.1:1") {
		t.Fatal("public beacon accepted")
	}
}

func TestBeaconMatchesAFriend(t *testing.T) {
	self := mustIdentity(t)
	friend := mustIdentity(t)
	stranger := mustIdentity(t)
	var got string
	s := &Service{
		id:      self,
		friends: func() []string { return []string{friend.ID()} },
		onLAN:   func(peer, addr string) { got = peer + " " + addr },
	}
	from := &net.UDPAddr{IP: net.ParseIP("192.168.1.9"), Port: 40000}
	s.handleBeacon(s.signedBeacon(friend, "192.168.1.9:7421", time.Now().Unix()), from)
	if got != friend.ID()+" 192.168.1.9:7421" {
		t.Fatalf("beacon %q", got)
	}
	s.handleBeacon(s.signedBeacon(friend, "8.8.8.8:7421", time.Now().Unix()), &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1})
	s.handleBeacon(s.signedBeacon(friend, "192.168.1.9:7421", time.Now().Unix()-120), from)
	s.handleBeacon(s.signedBeacon(stranger, "192.168.1.8:7421", time.Now().Unix()), &net.UDPAddr{IP: net.ParseIP("192.168.1.8"), Port: 1})
	s.handleBeacon(s.signedBeacon(friend, "192.168.1.50:7421", time.Now().Unix()), from)
	if got != friend.ID()+" 192.168.1.9:7421" {
		t.Fatalf("beacon changed to %q", got)
	}
}

func (s *Service) signedBeacon(id *identity.Identity, addr string, unix int64) []byte {
	old := s.id
	s.id = id
	pkt := s.beaconPacket(addr, unix)
	s.id = old
	return pkt
}

func TestConnectPacket(t *testing.T) {
	got := encodeConnect("abc")
	want := []byte{0x10, 0x0f, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 60, 0x00, 0x03, 'a', 'b', 'c'}
	if string(got) != string(want) {
		t.Fatalf("connect %x", got)
	}
}

func TestFreshSeq(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if !freshSeq(now.Unix(), now) || !freshSeq(now.Unix()-10*60, now) {
		t.Fatal("fresh rejected")
	}
	if freshSeq(now.Unix()-20*60, now) || freshSeq(now.Unix()+300, now) {
		t.Fatal("stale accepted")
	}
}
