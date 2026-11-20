package discover

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// A running app subscribes to its own inbox. Letters for that glyph ID
// are published there. The payload is a signed packet. The relay cannot
// produce a signature for a key it does not hold.
type target struct {
	addr string
	path string
}

type relays struct {
	all []*relay
}

func newRelays(targets []target, dial func() (net.Conn, error), onPub func(topic string, payload []byte)) *relays {
	if dial != nil {
		return &relays{all: []*relay{newRelay(nil, dial, onPub)}}
	}
	var all []*relay
	for _, t := range targets {
		all = append(all, newRelay([]target{t}, nil, onPub))
	}
	if len(all) == 0 {
		return nil
	}
	return &relays{all: all}
}

func (g *relays) run(done <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	if g == nil {
		return
	}
	var inner sync.WaitGroup
	for _, r := range g.all {
		inner.Add(1)
		go r.run(done, &inner)
	}
	inner.Wait()
}

func (g *relays) Subscribe(topic string) error {
	if g == nil || len(g.all) == 0 {
		return errNoPath
	}
	errc := make(chan error, len(g.all))
	for _, r := range g.all {
		go func(r *relay) { errc <- r.Subscribe(topic) }(r)
	}
	ok := false
	var last error
	for range g.all {
		if err := <-errc; err != nil {
			last = err
		} else {
			ok = true
		}
	}
	if ok {
		return nil
	}
	if last == nil {
		last = errNoPath
	}
	return last
}

func (g *relays) Publish(topic string, payload []byte) error {
	if g == nil || len(g.all) == 0 {
		return errNoPath
	}
	errc := make(chan error, len(g.all))
	for _, r := range g.all {
		go func(r *relay) { errc <- r.Publish(topic, payload) }(r)
	}
	ok := false
	var last error
	for range g.all {
		if err := <-errc; err != nil {
			last = err
		} else {
			ok = true
		}
	}
	if ok {
		return nil
	}
	if last == nil {
		last = errNoPath
	}
	return last
}

func (g *relays) connected() bool {
	if g == nil {
		return false
	}
	for _, r := range g.all {
		if r.connected() {
			return true
		}
	}
	return false
}

func (g *relays) drop() {
	if g == nil {
		return
	}
	for _, r := range g.all {
		r.drop()
	}
}

type relay struct {
	targets []target
	dial    func() (net.Conn, error)
	onPub   func(topic string, payload []byte)

	mu      sync.Mutex
	conn    net.Conn
	writeMu sync.Mutex
	want    map[string]struct{}
	acked   map[string]struct{}
	pubWait map[uint16]chan struct{}
	subWait map[uint16]chan struct{}
	next    uint16
}

func newRelay(targets []target, dial func() (net.Conn, error), onPub func(topic string, payload []byte)) *relay {
	return &relay{
		targets: append([]target(nil), targets...),
		dial:    dial,
		onPub:   onPub,
		want:    map[string]struct{}{},
		acked:   map[string]struct{}{},
		pubWait: map[uint16]chan struct{}{},
		subWait: map[uint16]chan struct{}{},
	}
}

func (r *relay) run(done <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		if err := r.connect(); err != nil {
			select {
			case <-done:
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			r.read()
		}()
		stopPing := make(chan struct{})
		go func() {
			tick := time.NewTicker(20 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-stopPing:
					return
				case <-readDone:
					return
				case <-tick.C:
					_ = r.write([]byte{0xC0, 0x00})
				}
			}
		}()
		r.resubscribe()
		select {
		case <-done:
			r.drop()
			<-readDone
			close(stopPing)
			return
		case <-readDone:
			close(stopPing)
			r.drop()
		}
		select {
		case <-done:
			return
		case <-time.After(time.Second):
		}
	}
}

func (r *relay) connect() error {
	conn, err := r.open()
	if err != nil {
		return err
	}
	if err := writeFrame(conn, encodeConnect(clientID())); err != nil {
		conn.Close()
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	hdr, body, err := readFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || hdr != 0x20 || len(body) < 2 || body[1] != 0 {
		conn.Close()
		return errNoPath
	}
	r.mu.Lock()
	r.conn = conn
	r.acked = map[string]struct{}{}
	r.mu.Unlock()
	return nil
}

func (r *relay) open() (net.Conn, error) {
	if r.dial != nil {
		return r.dial()
	}
	var last error
	for _, target := range r.targets {
		host, _, err := net.SplitHostPort(target.addr)
		if err != nil {
			last = err
			continue
		}
		var conn net.Conn
		if target.path == "" {
			dialer := &net.Dialer{Timeout: 6 * time.Second}
			conn, err = tls.DialWithDialer(dialer, "tcp", target.addr, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host})
		} else {
			conn, err = dialWebSocket(target.addr, target.path)
		}
		if err != nil {
			last = err
			continue
		}
		return conn, nil
	}
	if last == nil {
		last = errNoPath
	}
	return nil, last
}

func (r *relay) connected() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conn != nil
}

func (r *relay) drop() {
	r.mu.Lock()
	conn := r.conn
	r.conn = nil
	r.acked = map[string]struct{}{}
	r.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (r *relay) read() {
	r.mu.Lock()
	conn := r.conn
	r.mu.Unlock()
	if conn == nil {
		return
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		hdr, body, err := readFrame(conn)
		if err != nil {
			return
		}
		switch hdr >> 4 {
		case 3:
			topic, payload, pid, qos, err := parsePublish(hdr, body)
			if err != nil {
				return
			}
			if qos > 0 && pid != 0 {
				_ = r.write(encodePuback(pid))
			}
			if r.onPub != nil {
				pkt := append([]byte(nil), payload...)
				go r.onPub(topic, pkt)
			}
		case 4:
			if len(body) >= 2 {
				r.signal(r.pubWait, binary.BigEndian.Uint16(body[:2]))
			}
		case 9:
			if len(body) >= 2 {
				r.signal(r.subWait, binary.BigEndian.Uint16(body[:2]))
			}
		case 13:
		}
	}
}

func (r *relay) signal(wait map[uint16]chan struct{}, pid uint16) {
	r.mu.Lock()
	ch := wait[pid]
	r.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (r *relay) Subscribe(topic string) error {
	r.mu.Lock()
	r.want[topic] = struct{}{}
	if _, ok := r.acked[topic]; ok {
		r.mu.Unlock()
		return nil
	}
	up := r.conn != nil
	r.mu.Unlock()
	if !up {
		return errNoPath
	}
	return r.sendSubscribe(topic)
}

func (r *relay) resubscribe() {
	r.mu.Lock()
	var topics []string
	for topic := range r.want {
		topics = append(topics, topic)
	}
	r.mu.Unlock()
	for _, topic := range topics {
		_ = r.sendSubscribe(topic)
	}
}

func (r *relay) sendSubscribe(topic string) error {
	pid, ch, err := r.begin(r.subWait)
	if err != nil {
		return err
	}
	defer r.end(r.subWait, pid)
	if err := r.write(encodeSubscribe(topic, pid)); err != nil {
		return err
	}
	select {
	case <-ch:
		r.mu.Lock()
		r.acked[topic] = struct{}{}
		r.mu.Unlock()
		return nil
	case <-time.After(4 * time.Second):
		return errNoPath
	}
}

func (r *relay) Publish(topic string, payload []byte) error {
	if len(payload) == 0 || len(payload) > 128*1024 {
		return errNoPath
	}
	pid, ch, err := r.begin(r.pubWait)
	if err != nil {
		return err
	}
	defer r.end(r.pubWait, pid)
	if err := r.write(encodePublish(topic, payload, pid)); err != nil {
		return err
	}
	select {
	case <-ch:
		return nil
	case <-time.After(4 * time.Second):
		return errNoPath
	}
}

func (r *relay) begin(wait map[uint16]chan struct{}) (uint16, chan struct{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil {
		return 0, nil, errNoPath
	}
	r.next++
	if r.next == 0 {
		r.next = 1
	}
	pid := r.next
	ch := make(chan struct{}, 1)
	wait[pid] = ch
	return pid, ch, nil
}

func (r *relay) end(wait map[uint16]chan struct{}, pid uint16) {
	r.mu.Lock()
	delete(wait, pid)
	r.mu.Unlock()
}

func (r *relay) write(pkt []byte) error {
	r.mu.Lock()
	conn := r.conn
	r.mu.Unlock()
	if conn == nil {
		return errNoPath
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	_, err := conn.Write(pkt)
	return err
}

func clientID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "g" + hex.EncodeToString(b[:])
}

func encodeConnect(id string) []byte {
	body := make([]byte, 0, 16+len(id))
	body = append(body, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60)
	body = append(body, byte(len(id)>>8), byte(len(id)))
	body = append(body, id...)
	return frame(0x10, body)
}

func encodeSubscribe(topic string, pid uint16) []byte {
	body := make([]byte, 2+2+len(topic)+1)
	binary.BigEndian.PutUint16(body[:2], pid)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(topic)))
	copy(body[4:], topic)
	body[len(body)-1] = 1
	return frame(0x82, body)
}

func encodePublish(topic string, payload []byte, pid uint16) []byte {
	body := make([]byte, 2+len(topic)+2+len(payload))
	binary.BigEndian.PutUint16(body[:2], uint16(len(topic)))
	copy(body[2:], topic)
	binary.BigEndian.PutUint16(body[2+len(topic):], pid)
	copy(body[4+len(topic):], payload)
	return frame(0x32, body)
}

func encodePublish0(topic string, payload []byte) []byte {
	body := make([]byte, 2+len(topic)+len(payload))
	binary.BigEndian.PutUint16(body[:2], uint16(len(topic)))
	copy(body[2:], topic)
	copy(body[2+len(topic):], payload)
	return frame(0x30, body)
}

func encodePuback(pid uint16) []byte {
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], pid)
	return frame(0x40, body[:])
}

func frame(hdr byte, body []byte) []byte {
	out := []byte{hdr}
	out = append(out, remlen(len(body))...)
	return append(out, body...)
}

func remlen(n int) []byte {
	var out []byte
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 || len(out) == 4 {
			break
		}
	}
	return out
}

func writeFrame(w io.Writer, pkt []byte) error {
	_, err := w.Write(pkt)
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, nil, err
	}
	hdr := b[0]
	n := 0
	mul := 1
	for i := 0; i < 4; i++ {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n += int(b[0]&0x7f) * mul
		mul *= 128
		if b[0]&0x80 == 0 {
			break
		}
		if i == 3 {
			return 0, nil, errNoPath
		}
	}
	if n < 0 || n > 256*1024 {
		return 0, nil, errNoPath
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr, body, nil
}

func parsePublish(hdr byte, body []byte) (topic string, payload []byte, pid uint16, qos byte, err error) {
	qos = (hdr >> 1) & 0x03
	if qos > 1 || len(body) < 2 {
		return "", nil, 0, 0, errNoPath
	}
	tlen := int(binary.BigEndian.Uint16(body[:2]))
	if tlen < 0 || len(body) < 2+tlen {
		return "", nil, 0, 0, errNoPath
	}
	topic = string(body[2 : 2+tlen])
	rest := body[2+tlen:]
	if qos > 0 {
		if len(rest) < 2 {
			return "", nil, 0, 0, errNoPath
		}
		pid = binary.BigEndian.Uint16(rest[:2])
		rest = rest[2:]
	}
	if strings.ContainsAny(topic, "\x00") {
		return "", nil, 0, 0, errNoPath
	}
	return topic, rest, pid, qos, nil
}

func inboxTopic(id string) string {
	sum := sha256.Sum256([]byte("glyph-inbox-v1\n" + id))
	return "g/" + hex.EncodeToString(sum[:])
}
