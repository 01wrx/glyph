// Package direct is peer-to-peer delivery between glyph IDs over the internet.
// The mailbox is not involved. A host name or IP is only where to connect.
// The glyph ID is who you are talking to.
//
// The dialer pins TLS 1.3 to the glyph ID it was given. The listener accepts
// a client only when that client proves a glyph ID already added on this
// machine. A letter is still sealed to the recipient, and it is kept only
// when the sender inside the seal is the same key that authenticated the
// connection. An address learned from the network is never dialed.
package direct

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"glyph/identity"
)

const (
	defaultListen = ":7421"
	maxFrame      = 96 * 1024
	frameLetter   = 1
	frameAck      = 2
	framePing     = 3
)

var errUnavailable = errors.New("direct: peer is not reachable")

// Node is one glyph ID's internet listener.
type Node struct {
	id       *identity.Identity
	cert     tls.Certificate
	friends  func() []string
	onLetter func(peer string, blob []byte) bool

	ln   net.Listener
	addr string

	mu       sync.Mutex
	reach    map[string]string
	sessions map[string]*session
	done     chan struct{}
	wg       sync.WaitGroup
}

type session struct {
	node    *Node
	peer    string
	conn    *tls.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	next    uint64
	wait    map[uint64]chan struct{}
	dead    chan struct{}
	closed  bool
}

// Listen accepts peers on addr. An empty addr uses port 7421 on every
// interface, so a reachable machine can be dialed from the internet.
// friends returns the glyph IDs this node will accept. onLetter reports
// whether the sealed blob was kept.
func Listen(addr string, id *identity.Identity, friends func() []string, onLetter func(peer string, blob []byte) bool) (*Node, error) {
	if id == nil || id.ID() == "" || friends == nil || onLetter == nil {
		return nil, errors.New("direct: no identity")
	}
	if strings.TrimSpace(addr) == "" {
		addr = defaultListen
	}
	cert, err := certificate(id.Private())
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil && addr == defaultListen {
		ln, err = net.Listen("tcp", ":0")
	}
	if err != nil {
		return nil, err
	}
	n := &Node{
		id:       id,
		cert:     cert,
		friends:  friends,
		onLetter: onLetter,
		ln:       ln,
		addr:     ln.Addr().String(),
		reach:    map[string]string{},
		sessions: map[string]*session{},
		done:     make(chan struct{}),
	}
	n.wg.Add(1)
	go n.accept()
	return n, nil
}

// Addr is the address this process is listening on.
func (n *Node) Addr() string {
	if n == nil {
		return ""
	}
	return n.addr
}

// SetReach stores an address the local user supplied for peer.
// The peer cannot choose this address.
func (n *Node) SetReach(peer, addr string) error {
	if n == nil {
		return errUnavailable
	}
	if _, err := identity.Parse(peer); err != nil {
		return errUnavailable
	}
	if err := ValidateDial(addr); err != nil {
		return err
	}
	n.mu.Lock()
	n.reach[peer] = addr
	n.mu.Unlock()
	return nil
}

// Drop closes an open connection and forgets the dial address.
func (n *Node) Drop(peer string) {
	if n == nil {
		return
	}
	n.mu.Lock()
	delete(n.reach, peer)
	s := n.sessions[peer]
	delete(n.sessions, peer)
	n.mu.Unlock()
	if s != nil {
		s.close()
	}
}

// Close stops the listener and open connections.
func (n *Node) Close() error {
	if n == nil {
		return nil
	}
	select {
	case <-n.done:
	default:
		close(n.done)
	}
	n.mu.Lock()
	for _, s := range n.sessions {
		s.close()
	}
	n.mu.Unlock()
	err := n.ln.Close()
	n.wg.Wait()
	return err
}

// Deliver sends one sealed blob to peer. It uses a connection that peer
// already opened, or dials the address the local user stored for that ID.
func (n *Node) Deliver(peer string, blob []byte) error {
	if n == nil || len(blob) == 0 || len(blob) > maxFrame {
		return errUnavailable
	}
	if _, err := identity.Parse(peer); err != nil {
		return errUnavailable
	}
	s := n.existing(peer)
	if s == nil {
		var err error
		s, err = n.dial(peer)
		if err != nil {
			return err
		}
	}
	return s.send(blob)
}

// ValidateDial accepts a host:port the local user typed. A public address
// is allowed. An unspecified address, a multicast address, or a missing
// port is not. The host is not the identity.
func ValidateDial(addr string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" {
		return errUnavailable
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errUnavailable
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return errUnavailable
		}
		return nil
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) > 253 || strings.ContainsAny(host, " \t\r\n/\\@") {
		return errUnavailable
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errUnavailable
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return errUnavailable
			}
		}
	}
	return nil
}

func (n *Node) accept() {
	defer n.wg.Done()
	for {
		conn, err := n.ln.Accept()
		if err != nil {
			return
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.handshake(conn, "")
		}()
	}
}

func (n *Node) dial(peer string) (*session, error) {
	n.mu.Lock()
	addr := n.reach[peer]
	n.mu.Unlock()
	if addr == "" {
		return nil, errUnavailable
	}
	if err := ValidateDial(addr); err != nil {
		return nil, err
	}
	pub, err := identity.Parse(peer)
	if err != nil {
		return nil, errUnavailable
	}
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", addr)
	if err != nil {
		return nil, errUnavailable
	}
	keepAlive(raw)
	conn := tls.Client(raw, n.clientConfig(pub))
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, errUnavailable
	}
	got, ok := peerOf(conn.ConnectionState())
	if !ok || got != peer {
		conn.Close()
		return nil, errUnavailable
	}
	return n.adopt(peer, conn), nil
}

func (n *Node) handshake(raw net.Conn, expect string) {
	keepAlive(raw)
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	conn := tls.Server(raw, n.serverConfig())
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{})
	peer, ok := peerOf(conn.ConnectionState())
	if !ok || !n.allowed(peer) || (expect != "" && peer != expect) {
		conn.Close()
		return
	}
	n.adopt(peer, conn)
}

func (n *Node) adopt(peer string, conn *tls.Conn) *session {
	s := &session{node: n, peer: peer, conn: conn, wait: map[uint64]chan struct{}{}, dead: make(chan struct{})}
	n.mu.Lock()
	if old := n.sessions[peer]; old != nil {
		old.close()
	}
	n.sessions[peer] = s
	n.mu.Unlock()
	n.wg.Add(1)
	go s.readLoop()
	go s.ping()
	return s
}

func (n *Node) existing(peer string) *session {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := n.sessions[peer]
	if s == nil || s.isClosed() {
		return nil
	}
	return s
}

func (n *Node) allowed(peer string) bool {
	for _, id := range n.friends() {
		if id == peer {
			return true
		}
	}
	return false
}

func (s *session) send(blob []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errUnavailable
	}
	s.next++
	counter := s.next
	ch := make(chan struct{})
	s.wait[counter] = ch
	s.mu.Unlock()
	if err := s.writeFrame(frameLetter, counter, blob); err != nil {
		s.cancel(counter)
		return errUnavailable
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-s.dead:
		return errUnavailable
	case <-timer.C:
		s.cancel(counter)
		return errUnavailable
	}
}

func (s *session) readLoop() {
	defer nDone(s)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		kind, counter, payload, err := readFrame(s.conn)
		if err != nil {
			s.close()
			return
		}
		switch kind {
		case frameAck:
			s.mu.Lock()
			ch := s.wait[counter]
			delete(s.wait, counter)
			s.mu.Unlock()
			if ch != nil {
				close(ch)
			}
		case framePing:
		case frameLetter:
			ok := s.node.onLetter(s.peer, payload)
			if ok {
				_ = s.writeFrame(frameAck, counter, nil)
			}
		default:
			s.close()
			return
		}
	}
}

func nDone(s *session) {
	s.node.wg.Done()
	s.node.mu.Lock()
	if s.node.sessions[s.peer] == s {
		delete(s.node.sessions, s.peer)
	}
	s.node.mu.Unlock()
}

func (s *session) ping() {
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.node.done:
			return
		case <-s.dead:
			return
		case <-tick.C:
			if s.isClosed() {
				return
			}
			_ = s.writeFrame(framePing, 0, nil)
		}
	}
}

func (s *session) writeFrame(kind byte, counter uint64, payload []byte) error {
	if len(payload) > maxFrame {
		return errUnavailable
	}
	body := make([]byte, 1+8+len(payload))
	body[0] = kind
	binary.BigEndian.PutUint64(body[1:9], counter)
	copy(body[9:], payload)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.isClosed() {
		return errUnavailable
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := s.conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := s.conn.Write(body)
	return err
}

func (s *session) cancel(counter uint64) {
	s.mu.Lock()
	delete(s.wait, counter)
	s.mu.Unlock()
}

func (s *session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.wait = map[uint64]chan struct{}{}
	s.mu.Unlock()
	close(s.dead)
	s.conn.Close()
}

func readFrame(r io.Reader) (kind byte, counter uint64, payload []byte, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 9 || n > 9+maxFrame {
		return 0, 0, nil, errUnavailable
	}
	buf := make([]byte, n)
	if _, err = io.ReadFull(r, buf); err != nil {
		return 0, 0, nil, err
	}
	return buf[0], binary.BigEndian.Uint64(buf[1:9]), buf[9:], nil
}

func keepAlive(raw net.Conn) {
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(30 * time.Second)
}

func (n *Node) serverConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{n.cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			pub, err := leafKey(raw)
			if err != nil {
				return err
			}
			id, err := identity.Format(pub)
			if err != nil || !n.allowed(id) {
				return errors.New("direct: rejected")
			}
			return nil
		},
	}
}

func (n *Node) clientConfig(expect ed25519.PublicKey) *tls.Config {
	want := append(ed25519.PublicKey(nil), expect...)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{n.cert},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			pub, err := leafKey(raw)
			if err != nil || subtle.ConstantTimeCompare(pub, want) != 1 {
				return errors.New("direct: rejected")
			}
			return nil
		},
	}
}

func leafKey(raw [][]byte) (ed25519.PublicKey, error) {
	if len(raw) == 0 {
		return nil, errors.New("direct: rejected")
	}
	cert, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return nil, errors.New("direct: rejected")
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("direct: rejected")
	}
	return pub, nil
}

func peerOf(st tls.ConnectionState) (string, bool) {
	if len(st.PeerCertificates) == 0 {
		return "", false
	}
	pub, ok := st.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", false
	}
	id, err := identity.Format(pub)
	if err != nil {
		return "", false
	}
	return id, true
}

func certificate(priv ed25519.PrivateKey) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	serial.Add(serial, big.NewInt(1))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}
