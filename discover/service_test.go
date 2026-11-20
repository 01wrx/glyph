package discover

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"glyph/identity"
)

func TestLookupDeliversTheBlob(t *testing.T) {
	one := newFakeDHT(t)
	two := newFakeDHT(t)
	boots := []string{one.addr(), two.addr()}
	alice := mustIdentity(t)
	bob := mustIdentity(t)
	eve := mustIdentity(t)
	var mu sync.Mutex
	var gotPeer string
	var got []byte
	bobSvc := testService(t, bob, func() []string { return []string{alice.ID()} }, func(peer string, blob []byte) bool {
		if peer != alice.ID() {
			return false
		}
		mu.Lock()
		gotPeer = peer
		got = append([]byte(nil), blob...)
		mu.Unlock()
		return true
	}, boots, nil)
	aliceSvc := testService(t, alice, func() []string { return []string{bob.ID()} }, func(string, []byte) bool { return true }, boots, nil)
	eveSvc := testService(t, eve, func() []string { return []string{bob.ID()} }, func(string, []byte) bool { return true }, boots, nil)
	if err := aliceSvc.publishOnce(); err != nil {
		t.Fatal(err)
	}
	if err := bobSvc.publishOnce(); err != nil {
		t.Fatal(err)
	}
	if err := eveSvc.publishOnce(); err != nil {
		t.Fatal(err)
	}
	blob := bytes.Repeat([]byte("m"), 2000)
	if err := aliceSvc.Deliver(bob.ID(), blob); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if gotPeer != alice.ID() || !bytes.Equal(got, blob) {
		mu.Unlock()
		t.Fatalf("bob got %s (%d bytes)", gotPeer, len(got))
	}
	mu.Unlock()
	if err := eveSvc.Deliver(bob.ID(), []byte("intruder")); err == nil {
		t.Fatal("bob accepted a glyph ID he had not added")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotPeer != alice.ID() || !bytes.Equal(got, blob) {
		t.Fatal("stranger changed the stored letter")
	}
}

func TestRelayDeliversTheBlob(t *testing.T) {
	broker := newFakeBroker(t)
	alice := mustIdentity(t)
	bob := mustIdentity(t)
	dial := func() (net.Conn, error) { return net.Dial("tcp", broker.addr()) }
	var mu sync.Mutex
	var got []byte
	bobSvc := testService(t, bob, func() []string { return []string{alice.ID()} }, func(peer string, blob []byte) bool {
		if peer != alice.ID() {
			return false
		}
		mu.Lock()
		got = append([]byte(nil), blob...)
		mu.Unlock()
		return true
	}, nil, dial)
	aliceSvc := testService(t, alice, func() []string { return []string{bob.ID()} }, func(string, []byte) bool { return true }, nil, dial)
	bobSvc.Watch(alice.ID())
	blob := []byte("sealed-over-relay-and-only-a-glyph-id")
	if err := aliceSvc.Deliver(bob.ID(), blob); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(got, blob) {
		t.Fatalf("relay blob %q", got)
	}
}

func TestStrangerPacketIsIgnored(t *testing.T) {
	bob := mustIdentity(t)
	alice := mustIdentity(t)
	eve := mustIdentity(t)
	called := false
	s := &Service{
		id:      bob,
		friends: func() []string { return []string{alice.ID()} },
		onLetter: func(string, []byte) bool {
			called = true
			return true
		},
		frags: map[string]*fragBuf{},
		wait:  map[string]waiter{},
	}
	token := bytes.Repeat([]byte{3}, 16)
	pkt, err := encodeSigned(eve.Private(), kindLetter, letterBody(token, 0, 1, []byte("intruder")))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(pkt[:5+len(letterBody(token, 0, 1, []byte("intruder")))], eve.Public()) {
		t.Fatal("signer is in the clear packet")
	}
	s.handle(nil, pkt)
	if called {
		t.Fatal("stranger reached onLetter")
	}
	good, err := encodeSigned(alice.Private(), kindLetter, letterBody(token, 0, 1, []byte("hi")))
	if err != nil {
		t.Fatal(err)
	}
	s.handle(nil, good)
	if !called {
		t.Fatal("friend letter was dropped")
	}
}

func TestExternalNeedsTwoNodes(t *testing.T) {
	one := newFakeDHT(t)
	two := newFakeDHT(t)
	solo, err := newDHT([]string{one.addr()}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer solo.Close()
	solo.learn()
	if solo.External() != "" {
		t.Fatalf("one node set %s", solo.External())
	}
	pair, err := newDHT([]string{one.addr(), two.addr()}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Close()
	pair.learn()
	if pair.External() == "" {
		t.Fatal("two nodes did not agree")
	}
	spoof, err := newDHT(nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer spoof.Close()
	la := spoof.conn.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: la.Port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pkt := append([]byte("d2:ip6:"), 8, 8, 8, 8, 0x1c, 0xfd)
	pkt = append(pkt, 'e')
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if spoof.External() != "" {
			t.Fatalf("unsolicited address %s", spoof.External())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTamperedPacketIsIgnored(t *testing.T) {
	id := mustIdentity(t)
	called := false
	s := &Service{
		id:       id,
		friends:  func() []string { return []string{id.ID()} },
		onLetter: func(string, []byte) bool { called = true; return true },
	}
	token := bytes.Repeat([]byte{7}, 16)
	pkt, err := encodeSigned(id.Private(), kindLetter, letterBody(token, 0, 1, []byte("hi")))
	if err != nil {
		t.Fatal(err)
	}
	pkt[len(pkt)-1] ^= 1
	s.handle(nil, pkt)
	if called {
		t.Fatal("tampered packet was accepted")
	}
}

func TestLiveRelayAndDHT(t *testing.T) {
	if os.Getenv("GLYPH_LIVE") != "1" {
		t.Skip()
	}
	alice := mustIdentity(t)
	bob := mustIdentity(t)
	var mu sync.Mutex
	var got []byte
	bobSvc, err := start(config{
		id: bob, friends: func() []string { return []string{alice.ID()} },
		onLetter: func(peer string, blob []byte) bool {
			if peer != alice.ID() {
				return false
			}
			mu.Lock()
			got = append([]byte(nil), blob...)
			mu.Unlock()
			return true
		},
		relays: defaultRelays(), quiet: true, ackWait: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bobSvc.Close()
	aliceSvc, err := start(config{
		id: alice, friends: func() []string { return []string{bob.ID()} },
		onLetter: func(string, []byte) bool { return true },
		relays:   defaultRelays(), quiet: true, ackWait: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer aliceSvc.Close()
	bobSvc.Watch(alice.ID())
	blob := []byte("live-relay")
	if err := aliceSvc.Deliver(bob.ID(), blob); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if !bytes.Equal(got, blob) {
		t.Fatalf("live blob %q", got)
	}
	mu.Unlock()

	dhtID := mustIdentity(t)
	node, err := start(config{
		id: dhtID, friends: func() []string { return nil },
		onLetter: func(string, []byte) bool { return false },
		boots:    publicBootstrap, quiet: true, ackWait: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if err := node.publishOnce(); err != nil {
		t.Fatal(err)
	}
	addr, seq, err := node.dht.Get(dhtID.Public())
	if err != nil {
		t.Fatal(err)
	}
	if addr != node.dht.External() || !freshSeq(seq, time.Now()) {
		t.Fatalf("dht %s seq %d external %s", addr, seq, node.dht.External())
	}
}

func testService(t *testing.T, id *identity.Identity, friends func() []string, on func(string, []byte) bool, boots []string, dial func() (net.Conn, error)) *Service {
	t.Helper()
	s, err := start(config{
		id: id, friends: friends, onLetter: on, boots: boots, dial: dial,
		allowLocal: true, quiet: true, ackWait: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type fakeDHT struct {
	conn  *net.UDPConn
	id    [20]byte
	mu    sync.Mutex
	store map[string]stored
}

type stored struct {
	v, k, sig string
	seq       int64
}

func newFakeDHT(t *testing.T) *fakeDHT {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDHT{conn: conn, store: map[string]stored{}}
	if _, err := randRead(f.id[:]); err != nil {
		t.Fatal(err)
	}
	go f.loop()
	t.Cleanup(func() { conn.Close() })
	return f
}

func randRead(b []byte) (int, error) {
	return copy(b, bytes.Repeat([]byte{9}, len(b))), nil
}

func (f *fakeDHT) addr() string { return f.conn.LocalAddr().String() }

func (f *fakeDHT) loop() {
	buf := make([]byte, 4096)
	for {
		n, from, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg, err := unmarshal(buf[:n])
		if err != nil {
			continue
		}
		m, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		q, _ := asString(m["q"])
		txn, _ := asString(m["t"])
		a, _ := m["a"].(map[string]any)
		var r map[string]any
		switch q {
		case "find_node", "ping":
			r = map[string]any{"id": string(f.id[:]), "nodes": f.compact()}
		case "get":
			r = map[string]any{"id": string(f.id[:]), "token": "ok", "nodes": f.compact()}
			target, _ := asString(a["target"])
			f.mu.Lock()
			it, found := f.store[target]
			f.mu.Unlock()
			if found {
				r["v"] = it.v
				r["k"] = it.k
				r["sig"] = it.sig
				r["seq"] = it.seq
			}
		case "put":
			token, _ := asString(a["token"])
			k, _ := asString(a["k"])
			v, _ := asString(a["v"])
			sig, _ := asString(a["sig"])
			seq, seqOK := asInt(a["seq"])
			if token != "ok" || !seqOK || len(k) != ed25519.PublicKeySize || !verifyPresence(ed25519.PublicKey(k), v, seq, []byte(sig)) {
				raw, err := marshal(map[string]any{"t": txn, "y": "e", "e": []any{int64(206), "bad"}})
				if err == nil {
					_, _ = f.conn.WriteToUDP(raw, from)
				}
				continue
			}
			sum := sha1.Sum([]byte(k))
			f.mu.Lock()
			prev, exists := f.store[string(sum[:])]
			if !exists || seq >= prev.seq {
				f.store[string(sum[:])] = stored{v: v, k: k, sig: sig, seq: seq}
			}
			f.mu.Unlock()
			r = map[string]any{"id": string(f.id[:])}
		default:
			continue
		}
		ip := from.IP.To4()
		if ip == nil {
			continue
		}
		var seen [6]byte
		copy(seen[:4], ip)
		binary.BigEndian.PutUint16(seen[4:], uint16(from.Port))
		raw, err := marshal(map[string]any{"ip": string(seen[:]), "r": r, "t": txn, "y": "r"})
		if err != nil {
			continue
		}
		_, _ = f.conn.WriteToUDP(raw, from)
	}
}

func (f *fakeDHT) compact() string {
	a := f.conn.LocalAddr().(*net.UDPAddr)
	b := make([]byte, 26)
	copy(b[:20], f.id[:])
	copy(b[20:24], a.IP.To4())
	binary.BigEndian.PutUint16(b[24:], uint16(a.Port))
	return string(b)
}

type fakeBroker struct {
	ln      net.Listener
	mu      sync.Mutex
	clients []*brokerClient
}

type brokerClient struct {
	conn    net.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	subs    map[string]struct{}
	broker  *fakeBroker
}

func newFakeBroker(t *testing.T) *fakeBroker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBroker{ln: ln}
	go b.accept()
	t.Cleanup(func() { ln.Close() })
	return b
}

func (b *fakeBroker) addr() string { return b.ln.Addr().String() }

func (b *fakeBroker) accept() {
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			return
		}
		c := &brokerClient{conn: conn, subs: map[string]struct{}{}, broker: b}
		b.mu.Lock()
		b.clients = append(b.clients, c)
		b.mu.Unlock()
		go c.loop()
	}
}

func (c *brokerClient) loop() {
	defer c.conn.Close()
	hdr, _, err := readFrame(c.conn)
	if err != nil || hdr>>4 != 1 {
		return
	}
	if err := c.write([]byte{0x20, 0x02, 0x00, 0x00}); err != nil {
		return
	}
	for {
		hdr, body, err := readFrame(c.conn)
		if err != nil {
			return
		}
		switch hdr >> 4 {
		case 8:
			if len(body) < 5 {
				return
			}
			pid := binary.BigEndian.Uint16(body[:2])
			tlen := int(binary.BigEndian.Uint16(body[2:4]))
			if len(body) < 4+tlen {
				return
			}
			topic := string(body[4 : 4+tlen])
			c.mu.Lock()
			c.subs[topic] = struct{}{}
			c.mu.Unlock()
			var ack []byte
			ack = append(ack, byte(pid>>8), byte(pid), 0)
			if err := c.write(frame(0x90, ack)); err != nil {
				return
			}
		case 3:
			topic, payload, pid, qos, err := parsePublish(hdr, body)
			if err != nil {
				return
			}
			if qos > 0 {
				if err := c.write(encodePuback(pid)); err != nil {
					return
				}
			}
			c.broker.fanout(topic, payload)
		case 12:
			if err := c.write([]byte{0xD0, 0x00}); err != nil {
				return
			}
		}
	}
}

func (c *brokerClient) write(pkt []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.conn.Write(pkt)
	return err
}

func (b *fakeBroker) fanout(topic string, payload []byte) {
	b.mu.Lock()
	clients := append([]*brokerClient(nil), b.clients...)
	b.mu.Unlock()
	pkt := encodePublish0(topic, payload)
	for _, c := range clients {
		c.mu.Lock()
		_, on := c.subs[topic]
		c.mu.Unlock()
		if on {
			_ = c.write(pkt)
		}
	}
}
