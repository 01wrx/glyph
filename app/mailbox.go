package app

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"glyph/client"

	mbox "glyph-mailbox"
)

// RunMailbox serves this owner's mailbox until the process is interrupted.
// The server is given only the public glyph ID.
func RunMailbox(dir, owner, addr string) error {
	if err := validateMailbox(addr); err != nil {
		return err
	}
	s, err := mbox.New(dir, owner)
	if err != nil {
		return err
	}
	if _, err := s.Start(addr); err != nil {
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	return s.Close()
}

// Setup attaches to a mailbox that is already up and speaks this protocol.
// If nothing is listening on this machine's mailbox port, it starts one.
// A stale protocol or a box that refuses this ID stays unset.
func (a *App) Setup() bool {
	a.mu.Lock()
	if a.starting {
		a.mu.Unlock()
		return false
	}
	if a.onlineLocked() {
		a.mu.Unlock()
		return true
	}
	if a.anyAnswered() {
		a.mu.Unlock()
		return false
	}
	addr := a.bindTarget()
	env := strings.TrimSpace(os.Getenv("GLYPH_MAILBOX"))
	if (a.prefs.Mailbox != "" && a.prefs.Mailbox != addr) || (env != "" && env != addr) {
		a.mu.Unlock()
		return false
	}
	var tried error
	if a.fail != nil {
		tried = a.fail[addr]
	}
	if !startable(tried) {
		a.mu.Unlock()
		return false
	}
	a.starting = true
	host := a.host
	owner := a.id.ID()
	dir := filepath.Join(a.home, "mailbox")
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.starting = false
		a.mu.Unlock()
	}()
	if host == nil {
		host = spawnMailbox
	}
	if err := host(dir, owner, addr); err != nil {
		return false
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		ok := a.onlineLocked()
		a.mu.Unlock()
		if ok {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (a *App) onlineLocked() bool {
	if a.client != nil {
		if err := a.client.Pull(); err == nil {
			return true
		}
		a.client.Close()
		a.client = nil
	}
	return a.probeLocked()
}

func (a *App) probeLocked() bool {
	a.fail = map[string]error{}
	for _, addr := range a.candidateAddrs() {
		pin, pinErr := a.pinFor(addr)
		if pinErr != nil {
			a.fail[addr] = a.probeUnpinned(addr)
			if answered(a.fail[addr]) {
				return false
			}
			continue
		}
		c, st, err := client.Attach(addr, a.id, a.store, pin)
		if err != nil || st != client.StateOnline || c == nil {
			if c != nil {
				c.Close()
			}
			if err == nil {
				err = errors.New("glyph: mailbox unset")
			}
			a.fail[addr] = err
			if answered(err) {
				return false
			}
			continue
		}
		if a.client != nil {
			a.client.Close()
		}
		a.client = c
		a.remember(addr, pin)
		return true
	}
	return false
}

func (a *App) probeUnpinned(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return mbox.ErrProtocol
}

func (a *App) pinFor(addr string) (ed25519.PublicKey, error) {
	if pin, ok := a.pins[addr]; ok && len(pin) == ed25519.PublicKeySize {
		return pin, nil
	}
	if addr == a.prefs.Mailbox && a.prefs.MailboxKey != "" {
		return parsePin(a.prefs.MailboxKey)
	}
	if addr == strings.TrimSpace(os.Getenv("GLYPH_MAILBOX")) {
		if key := strings.TrimSpace(os.Getenv("GLYPH_MAILBOX_KEY")); key != "" {
			return parsePin(key)
		}
	}
	if addr == a.bindTarget() {
		return mbox.LoadPub(filepath.Join(a.home, "mailbox"))
	}
	return nil, errors.New("glyph: mailbox key unset")
}

func parsePin(s string) (ed25519.PublicKey, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != hex.EncodedLen(ed25519.PublicKeySize) {
		return nil, errors.New("glyph: mailbox key unset")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return mbox.ParsePin(raw)
}

func (a *App) candidateAddrs() []string {
	if a.candidates != nil {
		out := make([]string, len(a.candidates))
		copy(out, a.candidates)
		return out
	}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || validateMailbox(s) != nil {
			return
		}
		for _, have := range out {
			if have == s {
				return
			}
		}
		out = append(out, s)
	}
	add(a.prefs.Mailbox)
	add(os.Getenv("GLYPH_MAILBOX"))
	add(a.bindTarget())
	return out
}

func (a *App) bindTarget() string {
	if a.bindAddr != "" {
		return a.bindAddr
	}
	return defaultBind()
}

func (a *App) remember(addr string, pin ed25519.PublicKey) {
	hexPin := hex.EncodeToString(pin)
	if a.prefs.Mailbox == addr && a.prefs.MailboxKey == hexPin {
		return
	}
	a.prefs.Mailbox = addr
	a.prefs.MailboxKey = hexPin
	_ = a.savePrefs()
}

func (a *App) anyAnswered() bool {
	for _, err := range a.fail {
		if answered(err) {
			return true
		}
	}
	return false
}

func answered(err error) bool {
	return errors.Is(err, client.ErrStale) ||
		errors.Is(err, mbox.ErrUnauthorized) ||
		errors.Is(err, mbox.ErrForbidden) ||
		errors.Is(err, mbox.ErrProtocol) ||
		errors.Is(err, mbox.ErrInvalid)
}

func startable(err error) bool {
	if err == nil || answered(err) || errors.Is(err, mbox.ErrPublicBind) {
		return false
	}
	var op *net.OpError
	return errors.As(err, &op)
}

func defaultBind() string {
	if ip := privateIPv4(); ip != "" {
		return net.JoinHostPort(ip, port)
	}
	return net.JoinHostPort("127.0.0.1", port)
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

func networkLabel() string {
	if ip := privateIPv4(); ip != "" {
		return ip
	}
	return "network unavailable"
}

func validateMailbox(addr string) error { return mbox.ValidateAddr(addr) }

func spawnMailbox(dir, owner, addr string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "mailbox", "-dir", dir, "-owner", owner, "-addr", addr)
	detach(cmd)
	return cmd.Start()
}
