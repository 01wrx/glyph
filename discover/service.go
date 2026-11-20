// Package discover delivers a sealed letter to a glyph ID.
//
// A glyph ID is a key. Another app that already has the whole ID can use it
// in three ways. On the same network, a signed beacon carries a private
// address and the existing direct connection is used. On the internet, the
// app signs the public UDP address after two lookup nodes report the same
// one, and writes that signature into the distributed hash table. The other
// app checks the signature before it sends. When that path is closed, both
// apps hand the same signed packet across a relay. The packet does not
// carry a glyph ID. The relay cannot mint a signature for a key it does not
// hold. A looked-up address is used only when the glyph
// ID being contacted signed it, and a public lookup that names a private
// address is ignored.
package discover

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"glyph/identity"
)

var errNoPath = errors.New("discover: peer is not reachable")

var publicBootstrap = []string{
	"router.bittorrent.com:6881",
	"router.utorrent.com:6881",
	"dht.transmissionbt.com:6881",
	"dht.libtorrent.org:25401",
}

func defaultRelays() []target {
	if v := strings.TrimSpace(os.Getenv("GLYPH_RELAY")); v != "" {
		if v == "off" {
			return nil
		}
		return []target{{addr: v}}
	}
	return []target{
		{addr: "broker.hivemq.com:8883"},
		{addr: "broker.emqx.io:8883"},
		{addr: "test.mosquitto.org:8883"},
		{addr: "broker.hivemq.com:8884", path: "/mqtt"},
		{addr: "broker.emqx.io:8084", path: "/mqtt"},
	}
}

// Service looks up glyph IDs and carries signed packets to them.
type Service struct {
	id         *identity.Identity
	friends    func() []string
	onLetter   func(peer string, blob []byte) bool
	tcpAddr    func() string
	onLAN      func(peer, addr string)
	allowLocal bool
	ackWait    time.Duration

	dht   *DHT
	relay *relays

	mu      sync.Mutex
	cache   map[string]cached
	wait    map[string]waiter
	frags   map[string]*fragBuf
	watched map[string]struct{}
	inbox   chan incoming
	done    chan struct{}
	stop    sync.Once
	wg      sync.WaitGroup
	beacon  *net.UDPConn
}

type cached struct {
	addr string
	seq  int64
	at   time.Time
}

type waiter struct {
	peer string
	ch   chan struct{}
}

type fragBuf struct {
	total  int
	got    int
	chunks [][]byte
	token  []byte
	when   time.Time
}

type incoming struct {
	from *net.UDPAddr
	pkt  []byte
}

type config struct {
	id         *identity.Identity
	friends    func() []string
	onLetter   func(string, []byte) bool
	tcpAddr    func() string
	onLAN      func(string, string)
	boots      []string
	relays     []target
	dial       func() (net.Conn, error)
	allowLocal bool
	quiet      bool
	ackWait    time.Duration
}

// Start announces this glyph ID and accepts letters for friends.
// tcpAddr is the private address put in a local beacon. onLAN is called
// when a friend's beacon names a private address.
func Start(id *identity.Identity, friends func() []string, onLetter func(string, []byte) bool, tcpAddr func() string, onLAN func(string, string)) (*Service, error) {
	return start(config{
		id: id, friends: friends, onLetter: onLetter, tcpAddr: tcpAddr, onLAN: onLAN,
		boots: publicBootstrap, relays: defaultRelays(), ackWait: 15 * time.Second,
	})
}

func start(c config) (*Service, error) {
	if c.id == nil || c.id.ID() == "" || c.friends == nil || c.onLetter == nil {
		return nil, errors.New("discover: no identity")
	}
	if c.ackWait <= 0 {
		c.ackWait = 15 * time.Second
	}
	s := &Service{
		id: c.id, friends: c.friends, onLetter: c.onLetter, tcpAddr: c.tcpAddr, onLAN: c.onLAN,
		allowLocal: c.allowLocal, ackWait: c.ackWait,
		cache: map[string]cached{}, wait: map[string]waiter{}, frags: map[string]*fragBuf{},
		watched: map[string]struct{}{}, inbox: make(chan incoming, 32), done: make(chan struct{}),
	}
	if len(c.boots) > 0 {
		d, err := newDHT(c.boots, c.allowLocal, func(from *net.UDPAddr, pkt []byte) {
			s.enqueue(from, pkt)
		})
		if err != nil && c.dial == nil && len(c.relays) == 0 {
			return nil, err
		}
		if err == nil {
			s.dht = d
		}
	}
	if c.dial != nil || len(c.relays) > 0 {
		s.relay = newRelays(c.relays, c.dial, func(topic string, payload []byte) {
			if topic == "" || len(payload) == 0 || payload[0] != 'G' {
				return
			}
			s.enqueue(nil, payload)
		})
	}
	if s.dht == nil && s.relay == nil {
		return nil, errors.New("discover: no path")
	}
	if s.relay != nil {
		s.wg.Add(1)
		go s.relay.run(s.done, &s.wg)
		s.wg.Add(1)
		go s.keepInbox()
	}
	s.wg.Add(1)
	go s.packetLoop()
	if s.dht != nil && !c.quiet {
		s.wg.Add(1)
		go s.publishLoop()
	}
	if !c.allowLocal {
		s.wg.Add(1)
		go s.beaconLoop()
	}
	return s, nil
}

func (s *Service) enqueue(from *net.UDPAddr, pkt []byte) {
	if _, _, _, ok := openSigned(pkt, s.friendKeys()); !ok {
		return
	}
	item := incoming{pkt: pkt}
	if from != nil {
		cp := *from
		item.from = &cp
	}
	select {
	case s.inbox <- item:
	default:
	}
}

func (s *Service) friendKeys() []ed25519.PublicKey {
	if s == nil || s.friends == nil {
		return nil
	}
	ids := s.friends()
	out := make([]ed25519.PublicKey, 0, len(ids))
	for _, id := range ids {
		if id == "" || id == s.id.ID() {
			continue
		}
		pub, err := identity.Parse(id)
		if err != nil {
			continue
		}
		out = append(out, pub)
	}
	return out
}

// Endpoint is the public UDP address the lookup currently sees, when it
// has been signed and published.
func (s *Service) Endpoint() string {
	if s == nil {
		return ""
	}
	if s.dht != nil {
		if ext := s.dht.External(); addrOK(ext, s.allowLocal) {
			return ext
		}
	}
	if s.relay != nil && s.relay.connected() {
		return "relay"
	}
	return ""
}

// Watch keeps a path open to peer.
func (s *Service) Watch(peer string) {
	if s == nil {
		return
	}
	if _, err := identity.Parse(peer); err != nil || peer == s.id.ID() {
		return
	}
	s.mu.Lock()
	if _, ok := s.watched[peer]; ok {
		s.mu.Unlock()
		return
	}
	s.watched[peer] = struct{}{}
	s.mu.Unlock()
	s.wg.Add(1)
	go s.maintain(peer)
}

// Drop forgets a looked-up address and stops keeping a path open.
func (s *Service) Drop(peer string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.watched, peer)
	delete(s.cache, peer)
	s.mu.Unlock()
}

// Deliver sends blob to peer and waits until that peer accepts it.
func (s *Service) Deliver(peer string, blob []byte) error {
	if s == nil || !s.allowed(peer) {
		return errNoPath
	}
	pub, err := identity.Parse(peer)
	if err != nil || peer == s.id.ID() {
		return errNoPath
	}
	parts := splitBlob(blob)
	if parts == nil {
		return errNoPath
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return errNoPath
	}
	key := hex.EncodeToString(token)
	ch := make(chan struct{})
	s.mu.Lock()
	s.wait[key] = waiter{peer: peer, ch: ch}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.wait, key)
		s.mu.Unlock()
	}()

	stop := make(chan struct{})
	defer close(stop)
	go s.tryUDP(stop, peer, pub, token, parts)
	go s.tryRelay(stop, peer, token, parts)

	timer := time.NewTimer(s.ackWait)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-s.done:
		return errNoPath
	case <-timer.C:
		return errNoPath
	}
}

func (s *Service) tryUDP(stop <-chan struct{}, peer string, pub ed25519.PublicKey, token []byte, parts [][]byte) {
	var dest *net.UDPAddr
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		if dest == nil && s.dht != nil {
			if addr, err := s.resolve(pub); err == nil {
				if u, err := net.ResolveUDPAddr("udp4", addr); err == nil {
					dest = u
				}
			}
		}
		if dest != nil {
			s.burst(dest, token, parts)
		}
		select {
		case <-stop:
			return
		case <-s.done:
			return
		case <-tick.C:
		}
	}
}

func (s *Service) tryRelay(stop <-chan struct{}, peer string, token []byte, parts [][]byte) {
	if s.relay == nil {
		return
	}
	topic := inboxTopic(peer)
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		_ = s.relay.Subscribe(inboxTopic(s.id.ID()))
		s.burstRelay(topic, token, parts)
		select {
		case <-stop:
			return
		case <-s.done:
			return
		case <-tick.C:
		}
	}
}

func (s *Service) burst(dest *net.UDPAddr, token []byte, parts [][]byte) {
	if s.dht == nil {
		return
	}
	punch, err := encodeSigned(s.id.Private(), kindPunch, punchBody(time.Now()))
	if err == nil {
		_ = s.dht.WriteTo(punch, dest)
	}
	s.writeParts(token, parts, func(pkt []byte) error {
		return s.dht.WriteTo(pkt, dest)
	})
}

func (s *Service) burstRelay(topic string, token []byte, parts [][]byte) {
	s.writeParts(token, parts, func(pkt []byte) error {
		return s.relay.Publish(topic, pkt)
	})
}

func (s *Service) writeParts(token []byte, parts [][]byte, send func([]byte) error) {
	priv := s.id.Private()
	for i, part := range parts {
		pkt, err := encodeSigned(priv, kindLetter, letterBody(token, i, len(parts), part))
		if err != nil {
			return
		}
		_ = send(pkt)
	}
}

func (s *Service) packetLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.done:
			return
		case item := <-s.inbox:
			s.handle(item.from, item.pkt)
		}
	}
}

func (s *Service) handle(from *net.UDPAddr, pkt []byte) {
	pub, kind, body, ok := openSigned(pkt, s.friendKeys())
	if !ok {
		return
	}
	peer, err := identity.Format(pub)
	if err != nil || peer == s.id.ID() || !s.allowed(peer) {
		return
	}
	switch kind {
	case kindAck:
		if len(body) != 16 {
			return
		}
		key := hex.EncodeToString(body)
		s.mu.Lock()
		w, waiting := s.wait[key]
		if waiting && w.peer == peer {
			delete(s.wait, key)
			close(w.ch)
		}
		s.mu.Unlock()
	case kindPunch:
	case kindLetter:
		full, token, done := s.addFrag(peer, body)
		if !done {
			return
		}
		if s.onLetter(peer, full) {
			s.ack(peer, token, from)
		}
	}
}

func (s *Service) ack(peer string, token []byte, from *net.UDPAddr) {
	pkt, err := encodeSigned(s.id.Private(), kindAck, token)
	if err != nil {
		return
	}
	if from != nil && s.dht != nil {
		_ = s.dht.WriteTo(pkt, from)
	}
	if s.relay != nil {
		_ = s.relay.Publish(inboxTopic(peer), pkt)
	}
}

func (s *Service) keepInbox() {
	defer s.wg.Done()
	topic := inboxTopic(s.id.ID())
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if s.relay != nil {
			_ = s.relay.Subscribe(topic)
		}
		select {
		case <-s.done:
			return
		case <-tick.C:
		}
	}
}

func (s *Service) addFrag(peer string, body []byte) ([]byte, []byte, bool) {
	if len(body) < 18 {
		return nil, nil, false
	}
	token := append([]byte(nil), body[:16]...)
	idx := int(body[16])
	count := int(body[17])
	data := body[18:]
	if count < 1 || count > maxFrags || idx >= count || len(data) > fragData {
		return nil, nil, false
	}
	key := peer + "/" + hex.EncodeToString(token)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, frag := range s.frags {
		if now.Sub(frag.when) > 20*time.Second {
			delete(s.frags, k)
		}
	}
	frag := s.frags[key]
	if frag == nil {
		if len(s.frags) >= 32 || s.assemblies(peer) >= maxAssemblies {
			return nil, nil, false
		}
		frag = &fragBuf{total: count, chunks: make([][]byte, count), token: token, when: now}
		s.frags[key] = frag
	}
	if frag.total != count || frag.chunks[idx] != nil {
		if frag.got == frag.total {
			return concat(frag.chunks), token, true
		}
		return nil, nil, false
	}
	frag.chunks[idx] = append([]byte(nil), data...)
	frag.got++
	frag.when = now
	if frag.got != frag.total {
		return nil, nil, false
	}
	full := concat(frag.chunks)
	delete(s.frags, key)
	if len(full) == 0 || len(full) > maxBlob {
		return nil, nil, false
	}
	return full, token, true
}

func (s *Service) assemblies(peer string) int {
	n := 0
	prefix := peer + "/"
	for key := range s.frags {
		if strings.HasPrefix(key, prefix) {
			n++
		}
	}
	return n
}

func concat(chunks [][]byte) []byte {
	var n int
	for _, c := range chunks {
		n += len(c)
	}
	out := make([]byte, 0, n)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func (s *Service) resolve(pub ed25519.PublicKey) (string, error) {
	if s.dht == nil {
		return "", errNoPath
	}
	id, err := identity.Format(pub)
	if err != nil {
		return "", errNoPath
	}
	s.mu.Lock()
	c, ok := s.cache[id]
	s.mu.Unlock()
	if ok && c.addr == "" && time.Since(c.at) < 20*time.Second {
		return "", errNoPath
	}
	if ok && c.addr != "" && time.Since(c.at) < 45*time.Second && freshSeq(c.seq, time.Now()) && addrOK(c.addr, s.allowLocal) {
		return c.addr, nil
	}
	addr, seq, err := s.dht.Get(pub)
	if err != nil || !freshSeq(seq, time.Now()) || !addrOK(addr, s.allowLocal) {
		s.mu.Lock()
		s.cache[id] = cached{at: time.Now()}
		s.mu.Unlock()
		return "", errNoPath
	}
	s.mu.Lock()
	s.cache[id] = cached{addr: addr, seq: seq, at: time.Now()}
	s.mu.Unlock()
	return addr, nil
}

func (s *Service) publishOnce() error {
	if s.dht == nil {
		return errNoPath
	}
	s.dht.learn()
	ext := s.dht.External()
	if !addrOK(ext, s.allowLocal) {
		return errNoPath
	}
	return s.dht.Put(s.id.Private(), ext, time.Now().Unix())
}

func (s *Service) publishLoop() {
	defer s.wg.Done()
	var last string
	var lastPut time.Time
	s.publishTick(&last, &lastPut)
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.publishTick(&last, &lastPut)
		}
	}
}

func (s *Service) publishTick(last *string, lastPut *time.Time) {
	if s.dht == nil {
		return
	}
	s.dht.learn()
	ext := s.dht.External()
	if !addrOK(ext, s.allowLocal) {
		return
	}
	if ext == *last && time.Since(*lastPut) < time.Minute {
		return
	}
	if s.dht.Put(s.id.Private(), ext, time.Now().Unix()) == nil {
		*last = ext
		*lastPut = time.Now()
	}
}

func (s *Service) maintain(peer string) {
	defer s.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	s.punch(peer)
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.mu.Lock()
			_, on := s.watched[peer]
			s.mu.Unlock()
			if !on {
				return
			}
			s.punch(peer)
		}
	}
}

func (s *Service) punch(peer string) {
	if s.dht == nil {
		return
	}
	pub, err := identity.Parse(peer)
	if err != nil {
		return
	}
	addr, err := s.resolve(pub)
	if err != nil {
		return
	}
	dest, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return
	}
	pkt, err := encodeSigned(s.id.Private(), kindPunch, punchBody(time.Now()))
	if err == nil {
		_ = s.dht.WriteTo(pkt, dest)
	}
}

func (s *Service) allowed(peer string) bool {
	for _, id := range s.friends() {
		if id == peer {
			return true
		}
	}
	return false
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.stop.Do(func() { close(s.done) })
	s.mu.Lock()
	beacon := s.beacon
	s.mu.Unlock()
	if beacon != nil {
		beacon.Close()
	}
	var err error
	if s.dht != nil {
		err = s.dht.Close()
	}
	if s.relay != nil {
		s.relay.drop()
	}
	s.wg.Wait()
	return err
}

func (s *Service) beaconLoop() {
	defer s.wg.Done()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 7421})
	if err != nil {
		return
	}
	s.mu.Lock()
	if s.closed() {
		s.mu.Unlock()
		conn.Close()
		return
	}
	s.beacon = conn
	s.mu.Unlock()
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		s.readBeacons(conn)
	}()
	defer func() {
		conn.Close()
		readers.Wait()
	}()
	enableBroadcast(conn)
	s.sendBeacon(conn)
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.sendBeacon(conn)
		}
	}
}

func (s *Service) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *Service) readBeacons(conn *net.UDPConn) {
	buf := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if s.closed() {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		s.handleBeacon(buf[:n], from)
	}
}

func (s *Service) sendBeacon(conn *net.UDPConn) {
	if s.tcpAddr == nil {
		return
	}
	addr := s.tcpAddr()
	if !lanOK(addr) {
		return
	}
	pkt := s.beaconPacket(addr, time.Now().Unix())
	if pkt == nil {
		return
	}
	_, _ = conn.WriteToUDP(pkt, &net.UDPAddr{IP: net.IPv4bcast, Port: 7421})
}

func (s *Service) beaconPacket(addr string, unix int64) []byte {
	body := make([]byte, 0, 12+len(addr))
	body = append(body, 'G', 'L', 1)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], uint64(unix))
	body = append(body, u[:]...)
	body = append(body, byte(len(addr)))
	body = append(body, addr...)
	sig := ed25519.Sign(s.id.Private(), body)
	return append(body, sig...)
}

func (s *Service) handleBeacon(pkt []byte, from *net.UDPAddr) {
	if s.onLAN == nil || from == nil || len(pkt) < 12+ed25519.SignatureSize || pkt[0] != 'G' || pkt[1] != 'L' || pkt[2] != 1 {
		return
	}
	unix := int64(binary.BigEndian.Uint64(pkt[3:11]))
	n := int(pkt[11])
	if n <= 0 || n > 64 || len(pkt) != 12+n+ed25519.SignatureSize {
		return
	}
	if unix > time.Now().Unix()+30 || time.Now().Unix()-unix > 30 {
		return
	}
	addr := string(pkt[12 : 12+n])
	if !lanOK(addr) || !beaconSource(addr, from) {
		return
	}
	sig := pkt[12+n:]
	signed := pkt[:12+n]
	for _, id := range s.friends() {
		pub, err := identity.Parse(id)
		if err != nil || id == s.id.ID() {
			continue
		}
		if ed25519.Verify(pub, signed, sig) {
			s.onLAN(id, addr)
			return
		}
	}
}
