package discover

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"
)

func dialWebSocket(addr, path string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	raw, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host})
	if err != nil {
		return nil, err
	}
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		raw.Close()
		return nil, err
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key[:]) + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: mqtt\r\n\r\n"
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.WriteString(raw, req); err != nil {
		raw.Close()
		return nil, err
	}
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 256)
	for !strings.Contains(string(buf), "\r\n\r\n") {
		if len(buf) > 4096 {
			raw.Close()
			return nil, errNoPath
		}
		n, err := raw.Read(tmp)
		if err != nil {
			raw.Close()
			return nil, err
		}
		buf = append(buf, tmp[:n]...)
	}
	_ = raw.SetDeadline(time.Time{})
	head := string(buf)
	if !strings.Contains(head, "101") {
		raw.Close()
		return nil, errNoPath
	}
	rest := buf[strings.Index(head, "\r\n\r\n")+4:]
	return &wsConn{raw: raw, rest: append([]byte(nil), rest...)}, nil
}

type wsConn struct {
	raw  net.Conn
	rest []byte
	in   []byte
}

func (c *wsConn) Read(p []byte) (int, error) {
	for len(c.in) == 0 {
		payload, err := c.next()
		if err != nil {
			return 0, err
		}
		c.in = payload
	}
	n := copy(p, c.in)
	c.in = c.in[n:]
	return n, nil
}

func (c *wsConn) next() ([]byte, error) {
	var msg []byte
	for {
		var hdr [2]byte
		if err := c.readFull(hdr[:]); err != nil {
			return nil, err
		}
		fin := hdr[0]&0x80 != 0
		op := hdr[0] & 0x0f
		n := int(hdr[1] & 0x7f)
		switch n {
		case 126:
			var ext [2]byte
			if err := c.readFull(ext[:]); err != nil {
				return nil, err
			}
			n = int(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if err := c.readFull(ext[:]); err != nil {
				return nil, err
			}
			n = int(binary.BigEndian.Uint64(ext[:]))
		}
		if n < 0 || n > 1<<20 {
			return nil, errNoPath
		}
		payload := make([]byte, n)
		if n > 0 {
			if err := c.readFull(payload); err != nil {
				return nil, err
			}
		}
		switch op {
		case 8:
			return nil, io.EOF
		case 9:
			_ = c.writeFrame(0xA, payload)
		case 10:
		case 0, 1, 2:
			msg = append(msg, payload...)
			if fin {
				return msg, nil
			}
		}
	}
}

func (c *wsConn) readFull(p []byte) error {
	for len(p) > 0 {
		if len(c.rest) > 0 {
			n := copy(p, c.rest)
			c.rest = c.rest[n:]
			p = p[n:]
			continue
		}
		n, err := c.raw.Read(p)
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) writeFrame(op byte, payload []byte) error {
	hdr := []byte{0x80 | op}
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n)|0x80)
	case n < 65536:
		hdr = append(hdr, 126|0x80, byte(n>>8), byte(n))
	default:
		return errNoPath
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)
	buf := make([]byte, len(hdr)+n)
	copy(buf, hdr)
	for i := 0; i < n; i++ {
		buf[len(hdr)+i] = payload[i] ^ mask[i%4]
	}
	_, err := c.raw.Write(buf)
	return err
}

func (c *wsConn) Close() error                       { return c.raw.Close() }
func (c *wsConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
