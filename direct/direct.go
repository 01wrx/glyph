// Package direct delivers sealed letters from one glyph ID to another on the
// same network. There is no mailbox and no directory.
//
// An announcement is signed by the sender and names only a private address.
// It does not contain the glyph ID. A listener who was already given that ID
// can recognize the signature. Anyone else cannot tell who sent it.
//
// The connection is TLS 1.3. The dialer requires the server key to be the
// glyph ID it meant to reach. The listener requires the client key to be a
// glyph ID it already added. The sealed letter's sender must be that same key.
package direct

import (
	"bytes"
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
	"sync"
	"time"

	"glyph/identity"

	mbox "glyph-mailbox"
)

const (
	beaconPort    = 7421
	maxFrame      = 96 * 1024
	maxBeacon     = 160
	maxAddr       = 64
	beaconVersion = 1
	skew          = 120 * time.Second
	sightTTL      = 45 * time.Second
	beaconEvery   = 2 * time.Second
)

var errUnavailable = errors.New("direct: peer is not here")

// Node is this glyph ID's listener and announcement.
type Node struct {
	id       *identity.Identity
	cert     tls.Certificate
	friends  func() []string
	onLetter func(peer string, blob []byte)

	ln   net.Listener
	udp  *net.UDPConn
	addr string
	find time.Duration

	mu    sync.Mutex
	peers map[string]sight
	conns map[net.Conn]struct{}
	done  chan struct{}
	wg    sync.WaitGroup
}

type sight struct {
	addr  string
	until time.Time
}

// Listen starts a direct listener. friends returns the glyph IDs this node
// will accept. onLetter receives one sealed blob from an authenticated peer.
func Listen(id *identity.Identity, friends func() []string, onLetter func(peer string, blob []byte)) (*Node, error) {
	if id == nil || id.ID() == "" || friends == nil || onLetter == nil {
		return nil, errors.New("direct: no identity")
	}
	cert, err := certificate(id.Private())
	if err != nil {
		return nil, err
	}
	ip := privateIPv4()
	if ip == "" {
		ip = "127.0.0.1"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil && ip != "127.0.0.1" {
		ip = "127.0.0.1"
		ln, err = net.Listen("tcp", net.JoinHostPort(ip, "0"))
	}
	if err != nil {
		return nil, err
	}
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || tcp.Port == 0 {
		ln.Close()
		return nil, errors.New("direct: no address")
	}
	n := &Node{
		id:       id,
		cert:     cert,
		friends:  friends,
		onLetter: onLetter,
		ln:       ln,
		addr:     net.JoinHostPort(ip, itoa(tcp.Port)),
		find:     3 * time.Second,
		peers:    map[string]sight{},
		conns:    map[net.Conn]struct{}{},
		done:     make(chan struct{}),
	}
	n.wg.Add(1)
	go n.accept()
	if conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: beaconPort}); err == nil {
		if err := enableBroadcast(conn); err != nil {
			conn.Close()
		} else {
			n.udp = conn
			n.wg.Add(2)
			go n.announce()
			go n.collect()
		}
	}
	return n, nil
}

// Addr is the private address this node announces.
func (n *Node) Addr() string {
	if n == nil {
		return ""
	}
	return n.addr
}

// SetFind is how long Deliver waits for an announcement.
func (n *Node) SetFind(d time.Duration) {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.find = d
	n.mu.Unlock()
}

// Close stops the listener and the announcement.
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
	for c := range n.conns {
		c.Close()
	}
	n.mu.Unlock()
	err := n.ln.Close()
	if n.udp != nil {
		if err2 := n.udp.Close(); err == nil {
			err = err2
		}
	}
	n.wg.Wait()
	return err
}

// Beacon is a signed announcement of this node's current address.
func (n *Node) Beacon() []byte {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	return packBeacon(n.id.Private(), n.addr, time.Now().Unix(), nonce[:])
}

// AcceptBeacon stores the address in a signed announcement when it belongs
// to a glyph ID this node already accepts.
func (n *Node) AcceptBeacon(packet []byte) bool {
	id, addr, ok := openBeacon(packet, time.Now(), n.friendKeys())
	if !ok || id == n.id.ID() {
		return false
	}
	n.mu.Lock()
	n.peers[id] = sight{addr: addr, until: time.Now().Add(sightTTL)}
	n.mu.Unlock()
	return true
}

// Deliver sends one sealed blob to peer. It waits briefly for an announcement
// of that glyph ID, then connects only to the signed private address.
func (n *Node) Deliver(peer string, blob []byte) error {
	if n == nil || len(blob) == 0 || len(blob) > maxFrame {
		return errUnavailable
	}
	if _, err := identity.Parse(peer); err != nil {
		return errUnavailable
	}
	n.mu.Lock()
	wait := n.find
	n.mu.Unlock()
	deadline := time.Now().Add(wait)
	for {
		addr, ok := n.lookup(peer)
		if ok {
			return n.send(peer, addr, blob)
		}
		if !time.Now().Before(deadline) {
			return errUnavailable
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (n *Node) lookup(peer string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	s, ok := n.peers[peer]
	if !ok || !time.Now().Before(s.until) {
		delete(n.peers, peer)
		return "", false
	}
	return s.addr, true
}

func (n *Node) accept() {
	defer n.wg.Done()
	for {
		conn, err := n.ln.Accept()
		if err != nil {
			return
		}
		if !remoteLAN(conn.RemoteAddr()) {
			conn.Close()
			continue
		}
		n.mu.Lock()
		n.conns[conn] = struct{}{}
		n.mu.Unlock()
		n.wg.Add(1)
		go n.serve(conn)
	}
}

func (n *Node) serve(raw net.Conn) {
	defer n.wg.Done()
	defer func() {
		raw.Close()
		n.mu.Lock()
		delete(n.conns, raw)
		n.mu.Unlock()
	}()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Server(raw, n.serverConfig())
	if err := conn.Handshake(); err != nil {
		return
	}
	peer, ok := peerID(conn.ConnectionState())
	if !ok || !n.allowed(peer) {
		return
	}
	blob, err := readFrame(timeoutReader{c: conn})
	if err != nil {
		return
	}
	n.onLetter(peer, blob)
	_, _ = conn.Write([]byte{1})
}

func (n *Node) send(peer, addr string, blob []byte) error {
	pub, err := identity.Parse(peer)
	if err != nil {
		return errUnavailable
	}
	if err := mbox.ValidateAddr(addr); err != nil {
		return errUnavailable
	}
	raw, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", addr)
	if err != nil {
		return errUnavailable
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Client(raw, n.clientConfig(pub))
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return errUnavailable
	}
	got, ok := peerID(conn.ConnectionState())
	if !ok || got != peer {
		return errUnavailable
	}
	if err := writeFrame(conn, blob); err != nil {
		return err
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
		return errUnavailable
	}
	return nil
}

func (n *Node) allowed(peer string) bool {
	for _, id := range n.friends() {
		if id == peer {
			return true
		}
	}
	return false
}

func (n *Node) friendKeys() []ed25519.PublicKey {
	ids := n.friends()
	out := make([]ed25519.PublicKey, 0, len(ids))
	for _, id := range ids {
		pub, err := identity.Parse(id)
		if err != nil {
			continue
		}
		out = append(out, pub)
	}
	return out
}

func (n *Node) announce() {
	defer n.wg.Done()
	dst, err := net.ResolveUDPAddr("udp4", "255.255.255.255:"+itoa(beaconPort))
	if err != nil {
		return
	}
	tick := time.NewTicker(beaconEvery)
	defer tick.Stop()
	send := func() {
		_, _ = n.udp.WriteToUDP(n.Beacon(), dst)
	}
	send()
	for {
		select {
		case <-n.done:
			return
		case <-tick.C:
			send()
		}
	}
}

func (n *Node) collect() {
	defer n.wg.Done()
	buf := make([]byte, maxBeacon)
	for {
		_ = n.udp.SetReadDeadline(time.Now().Add(time.Second))
		k, _, err := n.udp.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-n.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		pkt := append([]byte(nil), buf[:k]...)
		n.AcceptBeacon(pkt)
	}
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

func packBeacon(priv ed25519.PrivateKey, addr string, unix int64, nonce []byte) []byte {
	if len(addr) == 0 || len(addr) > maxAddr || len(nonce) != 16 {
		return nil
	}
	body := beaconBody(addr, unix, nonce)
	sig := ed25519.Sign(priv, body)
	out := make([]byte, 0, 2+len(addr)+8+16+ed25519.SignatureSize)
	out = append(out, beaconVersion, byte(len(addr)))
	out = append(out, addr...)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], uint64(unix))
	out = append(out, u[:]...)
	out = append(out, nonce...)
	out = append(out, sig...)
	return out
}

func openBeacon(packet []byte, now time.Time, keys []ed25519.PublicKey) (id, addr string, ok bool) {
	if len(packet) < 2+8+16+ed25519.SignatureSize || len(packet) > maxBeacon || packet[0] != beaconVersion {
		return "", "", false
	}
	addrLen := int(packet[1])
	if addrLen == 0 || addrLen > maxAddr || len(packet) != 2+addrLen+8+16+ed25519.SignatureSize {
		return "", "", false
	}
	addr = string(packet[2 : 2+addrLen])
	rest := packet[2+addrLen:]
	unix := int64(binary.BigEndian.Uint64(rest[:8]))
	nonce := rest[8:24]
	sig := rest[24:]
	if err := mbox.ValidateAddr(addr); err != nil {
		return "", "", false
	}
	delta := time.Unix(unix, 0).Sub(now)
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return "", "", false
	}
	body := beaconBody(addr, unix, nonce)
	matched := ""
	for _, pub := range keys {
		if ed25519.Verify(pub, body, sig) {
			got, err := identity.Format(pub)
			if err != nil {
				return "", "", false
			}
			if matched != "" {
				return "", "", false
			}
			matched = got
		}
	}
	if matched == "" {
		return "", "", false
	}
	return matched, addr, true
}

func beaconBody(addr string, unix int64, nonce []byte) []byte {
	var b bytes.Buffer
	b.WriteString("glyph-direct-v1")
	b.WriteByte(0)
	b.WriteByte(byte(len(addr)))
	b.WriteString(addr)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], uint64(unix))
	b.Write(u[:])
	b.Write(nonce)
	return b.Bytes()
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

func peerID(st tls.ConnectionState) (string, bool) {
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

func writeFrame(w io.Writer, blob []byte) error {
	if len(blob) == 0 || len(blob) > maxFrame {
		return errUnavailable
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(blob)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(blob)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrame {
		return nil, errUnavailable
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

type timeoutReader struct{ c net.Conn }

func (t timeoutReader) Read(p []byte) (int, error) {
	_ = t.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	return t.c.Read(p)
}

func remoteLAN(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func privateIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip != nil && ip.IsPrivate() {
				return ip.String()
			}
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
