package discover

import (
	"crypto/ed25519"
	"crypto/sha1"
	"fmt"
	"net"
	"strconv"
	"time"
)

// presenceMsg is the BEP 44 buffer for a string value.
// The DHT slot is only a hash. This signature is what a peer trusts.
func presenceMsg(value string, seq int64) []byte {
	return []byte(fmt.Sprintf("3:seqi%de1:v%d:%s", seq, len(value), value))
}

func targetOf(pub ed25519.PublicKey) [20]byte {
	return sha1.Sum([]byte(pub))
}

func signPresence(priv ed25519.PrivateKey, value string, seq int64) []byte {
	return ed25519.Sign(priv, presenceMsg(value, seq))
}

func verifyPresence(pub ed25519.PublicKey, value string, seq int64, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || len(value) == 0 || len(value) > 64 {
		return false
	}
	return ed25519.Verify(pub, presenceMsg(value, seq), sig)
}

func freshSeq(seq int64, now time.Time) bool {
	u := now.Unix()
	return seq <= u+120 && u-seq <= 15*60
}

// routable reports whether ip may be used as a looked-up address.
// A public lookup result that is private, link-local, or loopback is rejected
// unless the process is talking to a local test node.
func routable(ip net.IP, allowLocal bool) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if allowLocal && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return true
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func addrOK(addr string, allowLocal bool) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	return routable(net.ParseIP(host), allowLocal)
}

func beaconSource(addr string, from *net.UDPAddr) bool {
	if from == nil || from.IP == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.Equal(from.IP)
}

func lanOK(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || len(addr) > 64 {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
