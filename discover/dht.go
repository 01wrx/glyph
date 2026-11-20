package discover

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"hash/crc32"
	"net"
	"strconv"
	"sync"
	"time"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// DHT is a small BEP 5 client that stores and loads a BEP 44 record.
// The record is signed by the glyph key. The hash only chooses the slot.
type DHT struct {
	conn       *net.UDPConn
	names      []string
	allowLocal bool
	onGlyph    func(*net.UDPAddr, []byte)

	mu      sync.Mutex
	nodeID  [20]byte
	idReady bool
	extIP   net.IP
	extPort int
	boot    []dhtNode
	bootAt  time.Time
	pending map[string]queryWait
	votes   map[string]map[string]struct{}
	byNode  map[string]string
	done    chan struct{}
	wg      sync.WaitGroup
	stop    sync.Once
}

type dhtNode struct {
	id   [20]byte
	addr net.UDPAddr
}

type queryWait struct {
	ch   chan map[string]any
	from net.UDPAddr
}

func newDHT(names []string, allowLocal bool, onGlyph func(*net.UDPAddr, []byte)) (*DHT, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	var id [20]byte
	if _, err := rand.Read(id[:]); err != nil {
		conn.Close()
		return nil, err
	}
	d := &DHT{
		conn:       conn,
		names:      append([]string(nil), names...),
		allowLocal: allowLocal,
		onGlyph:    onGlyph,
		nodeID:     id,
		pending:    map[string]queryWait{},
		votes:      map[string]map[string]struct{}{},
		byNode:     map[string]string{},
		done:       make(chan struct{}),
	}
	d.wg.Add(1)
	go d.readLoop()
	return d, nil
}

func (d *DHT) Close() error {
	if d == nil {
		return nil
	}
	d.stop.Do(func() { close(d.done) })
	err := d.conn.Close()
	d.wg.Wait()
	return err
}

func (d *DHT) External() string {
	if d == nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.extIP == nil || d.extPort == 0 {
		return ""
	}
	return net.JoinHostPort(d.extIP.String(), strconv.Itoa(d.extPort))
}

func (d *DHT) WriteTo(pkt []byte, to *net.UDPAddr) error {
	if d == nil || to == nil {
		return errNoPath
	}
	_, err := d.conn.WriteToUDP(pkt, to)
	return err
}

func (d *DHT) learn() {
	nodes := d.bootstrap()
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n dhtNode) {
			defer wg.Done()
			id := d.selfID()
			_, _ = d.query(n.addr, "find_node", map[string]any{
				"id":     string(id[:]),
				"target": string(id[:]),
			})
		}(n)
	}
	wg.Wait()
}

// Put stores addr under the glyph public key. seq must increase each write.
func (d *DHT) Put(priv ed25519.PrivateKey, addr string, seq int64) error {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return errNoPath
	}
	target := targetOf(pub)
	sig := signPresence(priv, addr, seq)
	nodes := d.closest(target)
	wrote := false
	for _, n := range nodes {
		r, err := d.query(n.addr, "get", map[string]any{
			"id":     string(d.idArg()),
			"target": string(target[:]),
		})
		if err != nil {
			continue
		}
		token, ok := asString(r["token"])
		if !ok || token == "" {
			continue
		}
		_, err = d.query(n.addr, "put", map[string]any{
			"id":     string(d.idArg()),
			"target": string(target[:]),
			"token":  token,
			"v":      addr,
			"k":      string(pub),
			"seq":    seq,
			"sig":    string(sig),
		})
		if err == nil {
			wrote = true
		}
	}
	if !wrote {
		return errNoPath
	}
	return nil
}

// Get returns the newest signed address for pub.
func (d *DHT) Get(pub ed25519.PublicKey) (string, int64, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", 0, errNoPath
	}
	target := targetOf(pub)
	var best string
	var bestSeq int64
	found := false
	for _, n := range d.closest(target) {
		r, err := d.query(n.addr, "get", map[string]any{
			"id":     string(d.idArg()),
			"target": string(target[:]),
		})
		if err != nil {
			continue
		}
		addr, aOK := asString(r["v"])
		k, kOK := asString(r["k"])
		sig, sOK := asString(r["sig"])
		seq, nOK := asInt(r["seq"])
		if !aOK || !kOK || !sOK || !nOK || len(k) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			continue
		}
		if !bytes.Equal([]byte(k), pub) {
			continue
		}
		got := sha1.Sum([]byte(k))
		if got != target || !verifyPresence(pub, addr, seq, []byte(sig)) {
			continue
		}
		if !found || seq > bestSeq {
			best, bestSeq, found = addr, seq, true
		}
	}
	if !found {
		return "", 0, errNoPath
	}
	return best, bestSeq, nil
}

func (d *DHT) readLoop() {
	defer d.wg.Done()
	buf := make([]byte, 4096)
	for {
		_ = d.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n == 0 || from == nil {
			continue
		}
		if buf[0] == 'G' {
			if d.onGlyph != nil {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				fromCopy := *from
				d.onGlyph(&fromCopy, pkt)
			}
			continue
		}
		msg, err := unmarshal(buf[:n])
		if err != nil {
			continue
		}
		m, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		txn, _ := asString(m["t"])
		if txn == "" {
			continue
		}
		d.mu.Lock()
		w, waiting := d.pending[txn]
		d.mu.Unlock()
		if !waiting || !sameNode(*from, w.from) {
			continue
		}
		if y, _ := asString(m["y"]); y == "r" {
			d.observe(*from, m)
		}
		select {
		case w.ch <- m:
		default:
		}
	}
}

func sameNode(a, b net.UDPAddr) bool {
	if a.Port == 0 || a.Port != b.Port {
		return false
	}
	left, right := a.IP.To4(), b.IP.To4()
	return left != nil && right != nil && left.Equal(right)
}

func (d *DHT) observe(reporter net.UDPAddr, msg map[string]any) {
	raw, _ := asString(msg["ip"])
	if raw == "" {
		if r, ok := msg["r"].(map[string]any); ok {
			raw, _ = asString(r["ip"])
		}
	}
	if len(raw) != 6 || reporter.IP == nil || reporter.Port == 0 {
		return
	}
	ip := net.IPv4(raw[0], raw[1], raw[2], raw[3]).To4()
	port := int(binary.BigEndian.Uint16([]byte(raw[4:6])))
	if ip == nil || port == 0 || !routable(ip, d.allowLocal) {
		return
	}
	repIP := reporter.IP.To4()
	if repIP == nil {
		return
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	node := net.JoinHostPort(repIP.String(), strconv.Itoa(reporter.Port))
	d.mu.Lock()
	defer d.mu.Unlock()
	if old, ok := d.byNode[node]; ok && old != addr {
		delete(d.votes[old], node)
		if len(d.votes[old]) == 0 {
			delete(d.votes, old)
		}
	}
	set := d.votes[addr]
	if set == nil {
		set = map[string]struct{}{}
		d.votes[addr] = set
	}
	set[node] = struct{}{}
	d.byNode[node] = addr
	d.promoteLocked()
}

func (d *DHT) promoteLocked() {
	best := ""
	bestN := 0
	second := 0
	for addr, set := range d.votes {
		n := len(set)
		if n == 0 || !addrOK(addr, d.allowLocal) {
			continue
		}
		if n > bestN {
			second = bestN
			best = addr
			bestN = n
		} else if n > second {
			second = n
		}
	}
	if bestN < 2 || bestN <= second {
		d.extIP = nil
		d.extPort = 0
		return
	}
	host, portStr, err := net.SplitHostPort(best)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 {
		return
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return
	}
	d.extIP = append(net.IP(nil), ip...)
	d.extPort = port
	if !d.idReady {
		d.nodeID = bep42(ip)
		d.idReady = true
	}
}

func bep42(ip net.IP) [20]byte {
	var masked [4]byte
	copy(masked[:], ip.To4())
	masked[3] = 0
	sum := crc32.Checksum(masked[:], crcTable)
	var id [20]byte
	_, _ = rand.Read(id[:])
	id[0] = byte(sum >> 24)
	id[1] = byte(sum >> 16)
	id[2] = byte(sum>>8)&0xf8 | id[2]&0x07
	return id
}

func (d *DHT) selfID() [20]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nodeID
}

func (d *DHT) idArg() string {
	id := d.selfID()
	return string(id[:])
}

func (d *DHT) query(to net.UDPAddr, q string, args map[string]any) (map[string]any, error) {
	var rnd [2]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	txn := string(rnd[:])
	ch := make(chan map[string]any, 1)
	asked := net.UDPAddr{IP: append(net.IP(nil), to.IP...), Port: to.Port}
	d.mu.Lock()
	if _, exists := d.pending[txn]; exists {
		d.mu.Unlock()
		return nil, errNoPath
	}
	d.pending[txn] = queryWait{ch: ch, from: asked}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.pending, txn)
		d.mu.Unlock()
	}()
	raw, err := marshal(map[string]any{
		"t": txn,
		"y": "q",
		"q": q,
		"a": args,
	})
	if err != nil {
		return nil, err
	}
	if _, err := d.conn.WriteToUDP(raw, &to); err != nil {
		return nil, err
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-d.done:
		return nil, errNoPath
	case <-timer.C:
		return nil, errNoPath
	case msg := <-ch:
		if y, _ := asString(msg["y"]); y != "r" {
			return nil, errNoPath
		}
		r, ok := msg["r"].(map[string]any)
		if !ok {
			return nil, errNoPath
		}
		return r, nil
	}
}

func (d *DHT) bootstrap() []dhtNode {
	d.mu.Lock()
	fresh := len(d.boot) > 0 && time.Since(d.bootAt) < 10*time.Minute
	if fresh {
		out := append([]dhtNode(nil), d.boot...)
		d.mu.Unlock()
		return out
	}
	names := append([]string(nil), d.names...)
	allow := d.allowLocal
	d.mu.Unlock()
	var nodes []dhtNode
	for _, name := range names {
		nodes = append(nodes, resolveName(name, allow)...)
	}
	if len(nodes) == 0 {
		return nil
	}
	d.mu.Lock()
	d.boot = nodes
	d.bootAt = time.Now()
	out := append([]dhtNode(nil), d.boot...)
	d.mu.Unlock()
	return out
}

func resolveName(hostport string, allowLocal bool) []dhtNode {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if !routable(ip, allowLocal) {
			return nil
		}
		return []dhtNode{{addr: net.UDPAddr{IP: ip.To4(), Port: port}}}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	var out []dhtNode
	for _, ip := range ips {
		if routable(ip, allowLocal) {
			out = append(out, dhtNode{addr: net.UDPAddr{IP: ip.To4(), Port: port}})
		}
	}
	return out
}

func (d *DHT) closest(target [20]byte) []dhtNode {
	known := map[string]dhtNode{}
	for _, n := range d.bootstrap() {
		known[n.addr.String()] = n
	}
	queried := map[string]bool{}
	var prev [20]byte
	stable := 0
	for round := 0; round < 8; round++ {
		list := nearest(known, target, 8)
		if len(list) == 0 {
			break
		}
		if !isZero(list[0].id) && list[0].id == prev {
			stable++
			if stable >= 2 {
				break
			}
		} else {
			stable = 0
			prev = list[0].id
		}
		var batch []dhtNode
		for _, n := range list {
			if queried[n.addr.String()] {
				continue
			}
			batch = append(batch, n)
			if len(batch) == 3 {
				break
			}
		}
		if len(batch) == 0 {
			break
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		got := false
		for _, n := range batch {
			queried[n.addr.String()] = true
			wg.Add(1)
			go func(n dhtNode) {
				defer wg.Done()
				r, err := d.query(n.addr, "find_node", map[string]any{
					"id":     string(d.idArg()),
					"target": string(target[:]),
				})
				if err != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				got = true
				if id, ok := asString(r["id"]); len(id) == 20 && ok {
					cur := known[n.addr.String()]
					copy(cur.id[:], id)
					cur.addr = n.addr
					known[n.addr.String()] = cur
				}
				if nodes, ok := asString(r["nodes"]); ok {
					for _, m := range parseCompact(nodes, d.allowLocal) {
						if _, seen := known[m.addr.String()]; !seen {
							known[m.addr.String()] = m
						}
					}
				}
			}(n)
		}
		wg.Wait()
		if !got {
			break
		}
	}
	return nearest(known, target, 8)
}

func nearest(known map[string]dhtNode, target [20]byte, limit int) []dhtNode {
	list := make([]dhtNode, 0, len(known))
	for _, n := range known {
		if n.addr.Port == 0 || n.addr.IP == nil {
			continue
		}
		list = append(list, n)
	}
	for i := 1; i < len(list); i++ {
		j := i
		for j > 0 && xorLess(list[j].id, list[j-1].id, target) {
			list[j], list[j-1] = list[j-1], list[j]
			j--
		}
	}
	if len(list) > limit {
		list = list[:limit]
	}
	return list
}

func xorLess(a, b, target [20]byte) bool {
	for i := 0; i < 20; i++ {
		da := a[i] ^ target[i]
		db := b[i] ^ target[i]
		if da < db {
			return true
		}
		if da > db {
			return false
		}
	}
	return false
}

func isZero(id [20]byte) bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

func parseCompact(s string, allowLocal bool) []dhtNode {
	b := []byte(s)
	var out []dhtNode
	for len(b) >= 26 {
		var n dhtNode
		copy(n.id[:], b[:20])
		ip := net.IPv4(b[20], b[21], b[22], b[23]).To4()
		port := int(b[24])<<8 | int(b[25])
		b = b[26:]
		if port == 0 || !routable(ip, allowLocal) {
			continue
		}
		n.addr = net.UDPAddr{IP: ip, Port: port}
		out = append(out, n)
	}
	return out
}
