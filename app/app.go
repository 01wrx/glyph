// Package app is the glyph window: one key, local transcripts, and a mailbox
// on this LAN. The mailbox sees ciphertext only.
package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"glyph/client"
	"glyph/identity"
	"glyph/seal"
	"glyph/transcript"
)

const (
	port       = "7420"
	maxLabel   = 256
	previewLen = 48
)

// App is one person's glyph on this machine.
type App struct {
	mu         sync.Mutex
	home       string
	id         *identity.Identity
	store      *transcript.Store
	prefs      prefs
	client     *client.Client
	open       string
	token      string
	network    string
	fail       map[string]error
	candidates []string
	pins       map[string]ed25519.PublicKey
	bindAddr   string
	host       func(dir, owner, addr string) error
	starting   bool
	srv        *http.Server
}

type prefs struct {
	Name       string `json:"name"`
	Theme      string `json:"theme"`
	AutoUpdate bool   `json:"auto_update"`
	Mailbox    string `json:"mailbox,omitempty"`
	MailboxKey string `json:"mailbox_key,omitempty"`
}

// DefaultHome is the per-user directory. GLYPH_HOME overrides it.
func DefaultHome() string {
	if h := strings.TrimSpace(os.Getenv("GLYPH_HOME")); h != "" {
		return h
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "glyph-home"
	}
	return filepath.Join(base, "glyph")
}

// Open loads the key and transcripts in home, or creates them.
func Open(home string) (*App, error) {
	if strings.TrimSpace(home) == "" {
		return nil, errors.New("glyph: no home")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	id, err := loadOrCreate(filepath.Join(home, "key"))
	if err != nil {
		return nil, err
	}
	store, err := transcript.Open(filepath.Join(home, "transcript"), id.ID())
	if err != nil {
		return nil, err
	}
	a := &App{
		home:    home,
		id:      id,
		store:   store,
		prefs:   prefs{Name: "you", Theme: "dark"},
		token:   newToken(),
		network: networkLabel(),
	}
	if err := a.loadPrefs(); err != nil {
		return nil, err
	}
	return a, nil
}

// Close closes the mailbox connection and the local window server.
// A mailbox this app started keeps running.
func (a *App) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	c := a.client
	srv := a.srv
	a.client = nil
	a.srv = nil
	a.mu.Unlock()
	var err error
	if c != nil {
		err = c.Close()
	}
	if srv != nil {
		if err2 := srv.Close(); err == nil {
			err = err2
		}
	}
	return err
}

func (a *App) touchLocked() { _ = a.onlineLocked() }

// OpenChat starts a conversation with a glyph ID, or selects one that
// already exists. The ID may omit the glyph: prefix. A prefix, a self ID,
// and anything that is not a full ID do nothing.
func (a *App) OpenChat(raw string) bool {
	id, err := normalizeID(raw)
	if err != nil || id == a.store.Self() {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.store.Conversation(id); err != nil {
		if !errors.Is(err, transcript.ErrNotFound) || a.store.Add(id, "") != nil {
			return false
		}
	}
	if a.client != nil {
		_ = a.client.Introduce(id)
	}
	a.open = id
	return true
}

// Send seals text to peer and hands it to the mailbox.
// Nothing is stored or cleared for the caller when the mailbox is offline,
// the peer is unknown, or the letter is rejected.
func (a *App) Send(peer, text string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	id, err := normalizeID(peer)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil && !a.onlineLocked() {
		return false
	}
	if _, err := a.store.Conversation(id); err != nil {
		return false
	}
	_ = a.client.Introduce(id)
	if err := a.client.Send(id, text, time.Now().Unix()); err != nil {
		return false
	}
	a.open = id
	return true
}

// SetName stores the local label shown as "you are".
func (a *App) SetName(name string) bool {
	name = strings.TrimSpace(name)
	if checkLabel(name) != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.prefs.Name
	a.prefs.Name = name
	if err := a.savePrefs(); err != nil {
		a.prefs.Name = old
		return false
	}
	return true
}

// SetTheme stores dark or light.
func (a *App) SetTheme(theme string) bool {
	if theme != "dark" && theme != "light" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.prefs.Theme
	a.prefs.Theme = theme
	if err := a.savePrefs(); err != nil {
		a.prefs.Theme = old
		return false
	}
	return true
}

// SetAutoUpdate stores the GitHub update preference. The window does not
// download a release on its own.
func (a *App) SetAutoUpdate(on bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.prefs.AutoUpdate
	a.prefs.AutoUpdate = on
	if err := a.savePrefs(); err != nil {
		a.prefs.AutoUpdate = old
		return false
	}
	return true
}

// RemoveFriend drops peer from this owner's mailbox. The local transcript stays.
func (a *App) RemoveFriend(peer string) bool {
	id, err := normalizeID(peer)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		return false
	}
	return a.client.Remove(id) == nil
}

// AcceptSuccessor follows a pending successor for this conversation.
// The mailbox learns the new id only after the conversation actually moves.
func (a *App) AcceptSuccessor(peer string) bool {
	id, err := normalizeID(peer)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	next, err := a.store.Accept(id)
	if err != nil {
		return false
	}
	if next == "" {
		return true
	}
	if a.client != nil {
		_ = a.client.Introduce(next)
	}
	if a.open == id {
		a.open = next
	}
	return true
}

// SetRecord chooses whether this conversation keeps letters, and for how many
// seconds. Zero seconds keeps them until the choice changes.
func (a *App) SetRecord(peer, keep string) bool {
	id, err := normalizeID(peer)
	if err != nil {
		return false
	}
	on, sec, err := parseKeep(keep)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store.SetRecord(id, on, sec) == nil
}

// Refresh reads this machine's LAN address again.
func (a *App) Refresh() {
	label := networkLabel()
	a.mu.Lock()
	a.network = label
	a.mu.Unlock()
}

// Select shows that conversation in the window.
func (a *App) Select(peer string) bool {
	id, err := normalizeID(peer)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.store.Conversation(id); err != nil {
		return false
	}
	a.open = id
	return true
}

func (a *App) snapshotLocked() stateJSON {
	sums, err := a.store.List()
	chats := make([]chatJSON, 0)
	open := ""
	if err == nil {
		self := a.store.Self()
		for _, sum := range sums {
			view, err := a.store.Conversation(sum.ID)
			if err != nil {
				continue
			}
			chat := chatJSON{
				ID:       sum.ID,
				Label:    label(sum.Name, sum.ID),
				Keep:     keepToken(sum.Keep, sum.For),
				Pending:  view.Pending,
				Unix:     sum.Unix,
				Preview:  preview(sum.Last),
				Messages: make([]msgJSON, 0, len(view.Messages)),
			}
			for _, e := range view.Messages {
				text := e.Text
				kind := "chat"
				if e.Kind == seal.KindSuccessor {
					text = e.Next
					kind = "successor"
				}
				chat.Messages = append(chat.Messages, msgJSON{
					Out:  e.Sender == self,
					Text: text,
					Unix: e.Unix,
					Kind: kind,
				})
			}
			if sum.ID == a.open {
				open = sum.ID
			}
			chats = append(chats, chat)
		}
	}
	if open == "" {
		a.open = ""
	}
	mail := "none"
	box, boxKey := "", ""
	if a.client != nil {
		mail = "online"
		box = a.prefs.Mailbox
		boxKey = a.prefs.MailboxKey
	}
	return stateJSON{
		Name:        a.prefs.Name,
		ID:          a.store.Self(),
		Theme:       a.prefs.Theme,
		AutoUpdate:  a.prefs.AutoUpdate,
		Network:     a.network,
		Mailbox:     mail,
		MailboxAddr: box,
		MailboxKey:  boxKey,
		Open:        open,
		Chats:       chats,
	}
}

func loadOrCreate(path string) (*identity.Identity, error) {
	id, err := identity.Load(path)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	id, err = identity.Generate()
	if err != nil {
		return nil, err
	}
	if err := id.Save(path); err != nil {
		return nil, err
	}
	return id, nil
}

func normalizeID(raw string) (string, error) {
	s := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		default:
			return r
		}
	}, raw)
	s = strings.ToLower(s)
	if !strings.HasPrefix(s, "glyph:") {
		s = "glyph:" + s
	}
	pub, err := identity.Parse(s)
	if err != nil {
		return "", err
	}
	return identity.Format(pub)
}

func checkLabel(name string) error {
	if name == "" || strings.ContainsAny(name, "\r\n") || !utf8.ValidString(name) || len(name) > maxLabel {
		return errors.New("glyph: invalid name")
	}
	return nil
}

func label(name, id string) string {
	if name != "" {
		return name
	}
	hexID := strings.TrimPrefix(id, "glyph:")
	if len(hexID) < 8 {
		return hexID
	}
	return hexID[:4] + "…" + hexID[len(hexID)-4:]
}

func preview(s string) string {
	r := []rune(s)
	if len(r) <= previewLen {
		return s
	}
	return string(r[:previewLen-1]) + "…"
}

func keepToken(keep bool, seconds int64) string {
	if !keep {
		return "off"
	}
	switch seconds {
	case 0, 86400, 604800, 2592000:
		return jsonInt(seconds)
	default:
		return "0"
	}
}

func parseKeep(v string) (bool, int64, error) {
	switch v {
	case "off":
		return false, 0, nil
	case "0", "forever":
		return true, 0, nil
	case "86400", "604800", "2592000":
		var n int64
		for _, c := range v {
			n = n*10 + int64(c-'0')
		}
		return true, n, nil
	default:
		return false, 0, errors.New("glyph: invalid record")
	}
}

func jsonInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Token is the secret the window must present. It is not written into an
// unauthenticated page.
func (a *App) Token() string {
	if a == nil {
		return ""
	}
	return a.token
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b)
}

func (a *App) loadPrefs() error {
	b, err := os.ReadFile(a.prefsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(b)))
	dec.DisallowUnknownFields()
	var p prefs
	if err := dec.Decode(&p); err != nil {
		return err
	}
	if p.Name != "" {
		if err := checkLabel(p.Name); err != nil {
			return err
		}
		a.prefs.Name = p.Name
	}
	if p.Theme == "light" || p.Theme == "dark" {
		a.prefs.Theme = p.Theme
	}
	a.prefs.AutoUpdate = p.AutoUpdate
	if p.MailboxKey != "" {
		if _, err := parsePin(p.MailboxKey); err != nil {
			return err
		}
		a.prefs.MailboxKey = strings.ToLower(strings.TrimSpace(p.MailboxKey))
	}
	if p.Mailbox != "" {
		if err := validateMailbox(p.Mailbox); err != nil {
			return err
		}
		a.prefs.Mailbox = p.Mailbox
	}
	return nil
}

func (a *App) savePrefs() error {
	raw, err := json.MarshalIndent(a.prefs, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeAtomic(a.prefsPath(), raw)
}

func (a *App) prefsPath() string { return filepath.Join(a.home, "prefs.json") }
