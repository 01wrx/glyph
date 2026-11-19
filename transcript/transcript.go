// Package transcript stores conversations on this machine, keyed by the
// friend's current glyph ID. A display name is a local label, never an address.
// Letters are delivered in sender-counter order. Unix time is not the sort key.
package transcript

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"glyph/identity"
	"glyph/seal"
)

const (
	maxHeld    = 64
	maxText    = 48 * 1024
	maxName    = 256
	maxCounter = uint64(1) << 32
	// maxForSec is 100 years. Longer than that is rejected.
	maxForSec = int64(100 * 365 * 24 * 3600)
	diskV     = 2
)

var (
	// ErrReplay means this sender counter was already delivered or is already held.
	ErrReplay = errors.New("transcript: replay")
	// ErrStranger means the sender is not a friend in this store.
	// A glyph ID with no successor in an existing chat stays a stranger.
	ErrStranger = errors.New("transcript: stranger")
	// ErrSuccessor means a successor was rejected. Only the current peer can
	// name their next glyph ID, and it must not collide with another chat.
	ErrSuccessor = errors.New("transcript: successor rejected")
	// ErrNotFound means there is no conversation under that glyph ID.
	ErrNotFound = errors.New("transcript: no conversation")
	// ErrRecipient means the letter is not addressed to this store's glyph ID.
	ErrRecipient = errors.New("transcript: recipient mismatch")
	// ErrInvalid means the letter or the on-disk store is not usable.
	ErrInvalid = errors.New("transcript: invalid")
)

// Entry is one delivered letter. Held letters are not entries yet.
// Unix is the sender's time and is not trusted. Kept is the local time this
// machine stored the letter, and retention uses Kept.
type Entry struct {
	Sender    string
	Recipient string
	Kind      seal.Kind
	Counter   uint64
	Unix      int64
	Kept      int64
	Text      string
	Next      string
}

// View is a copy of one conversation. ID is the friend's current glyph ID.
// Name is a local label. Messages are in delivery order, which follows each
// sender's counter and does not follow Unix time.
type View struct {
	ID       string
	Name     string
	Keep     bool
	For      int64
	Pending  string
	Messages []Entry
}

// Store is the local transcript for one static glyph ID.
type Store struct {
	mu   sync.Mutex
	dir  string
	self string
	conv map[string]*conv
	now  func() time.Time
}

type conv struct {
	Peer        string
	Name        string
	Keep        bool
	For         int64
	SelfNext    uint64
	PeerNext    uint64
	PendingNext string
	Follow      bool
	Reach       string
	Log         []Entry
	Held        map[uint64]Entry
}

// Open loads the store in dir for selfID, or creates an empty one.
// Opening the same directory as a different glyph ID is rejected.
func Open(dir, selfID string) (*Store, error) {
	self, err := canonical(selfID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, self: self, conv: map[string]*conv{}}
	path := s.path()
	_, mainErr := os.Stat(path)
	_, tmpErr := os.Stat(path + ".tmp")
	if errors.Is(mainErr, os.ErrNotExist) && errors.Is(tmpErr, os.ErrNotExist) {
		if err := s.persist(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	if s.expireAll() {
		if err := s.persist(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Self is the glyph ID this store receives mail for.
func (s *Store) Self() string { return s.self }

// Add starts a conversation with a glyph ID that was handed to us.
// name is a local label and may be empty. It is not an address.
// An ID that a chat already named as its successor is rejected. That chat
// follows the ID by accepting it.
func (s *Store) Add(peerID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := canonical(peerID)
	if err != nil {
		return err
	}
	if peer == s.self {
		return ErrInvalid
	}
	if _, ok := s.conv[peer]; ok {
		return ErrInvalid
	}
	if s.nextTaken(peer, nil) {
		return ErrSuccessor
	}
	if err := checkName(name); err != nil {
		return err
	}
	snap := s.snapshot()
	s.conv[peer] = &conv{
		Peer:     peer,
		Name:     name,
		Keep:     true,
		SelfNext: 1,
		PeerNext: 1,
		Held:     map[uint64]Entry{},
	}
	if err := s.persist(); err != nil {
		s.conv = snap
		return err
	}
	return nil
}

// SetReach stores the host:port the local user uses to dial this glyph ID.
// An empty address clears it. The host is not an identity.
func (s *Store) SetReach(peerID, addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := canonical(peerID)
	if err != nil {
		return err
	}
	c, ok := s.conv[peer]
	if !ok {
		return ErrNotFound
	}
	addr = strings.TrimSpace(addr)
	if strings.ContainsAny(addr, " \t\r\n") || len(addr) > 253 {
		return ErrInvalid
	}
	snap := s.snapshot()
	c.Reach = addr
	if err := s.persist(); err != nil {
		s.conv = snap
		return err
	}
	return nil
}

// Reach is the dial address stored for peerID.
func (s *Store) Reach(peerID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := canonical(peerID)
	if err != nil {
		return "", err
	}
	c, ok := s.conv[peer]
	if !ok {
		return "", ErrNotFound
	}
	return c.Reach, nil
}

// SetName changes the local label. The conversation stays under the glyph ID.
func (s *Store) SetName(peerID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := canonical(peerID)
	if err != nil {
		return err
	}
	c, ok := s.conv[peer]
	if !ok {
		return ErrNotFound
	}
	if err := checkName(name); err != nil {
		return err
	}
	snap := s.snapshot()
	c.Name = name
	if err := s.persist(); err != nil {
		s.conv = snap
		return err
	}
	return nil
}

// SetRecord chooses whether this conversation keeps a local history, and for
// how many seconds. Zero seconds keeps it until the choice changes. A negative
// duration is rejected. Turning the record off deletes the stored letters.
// The counters stay, so a letter cannot be replayed into a chat that is not kept.
func (s *Store) SetRecord(peerID string, keep bool, seconds int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := canonical(peerID)
	if err != nil {
		return err
	}
	c, ok := s.conv[peer]
	if !ok {
		return ErrNotFound
	}
	if seconds < 0 || seconds > maxForSec {
		return ErrInvalid
	}
	if !keep {
		seconds = 0
	}
	snap := s.snapshot()
	c.Keep = keep
	c.For = seconds
	if !keep {
		c.Log = nil
		for k, e := range c.Held {
			e.Text = ""
			c.Held[k] = e
		}
	}
	c.expire(s.clock())
	if err := s.persist(); err != nil {
		s.conv = snap
		return err
	}
	return nil
}

// Summary is one conversation without its held letters.
// Last is the newest delivered letter. For a successor, Last is the next
// glyph ID. Unix is that letter's send time. Kept is when this machine stored
// it, and list order follows Kept.
type Summary struct {
	ID   string
	Name string
	Keep bool
	For  int64
	Last string
	Unix int64
	Kept int64
}

// List returns every conversation after dropping expired letters.
// Held letters stay out of Last. Order is newest stored letter first, then
// the glyph ID. A name is a local label, not an address.
func (s *Store) List() ([]Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.snapshot()
	if s.expireAll() {
		if err := s.persist(); err != nil {
			s.conv = snap
			return nil, err
		}
	}
	out := make([]Summary, 0, len(s.conv))
	for _, c := range s.conv {
		sum := Summary{ID: c.Peer, Name: c.Name, Keep: c.Keep, For: c.For}
		if n := len(c.Log); n > 0 {
			e := c.Log[n-1]
			sum.Unix = e.Unix
			sum.Kept = e.Kept
			if e.Kind == seal.KindSuccessor {
				sum.Last = e.Next
			} else {
				sum.Last = e.Text
			}
		}
		out = append(out, sum)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kept != out[j].Kept {
			return out[i].Kept > out[j].Kept
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Conversation returns a copy of the chat stored under this glyph ID.
// Names are not accepted here. A prefix of an ID is not accepted.
func (s *Store) Conversation(peerID string) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := canonical(peerID)
	if err != nil {
		return View{}, err
	}
	c, ok := s.conv[peer]
	if !ok {
		return View{}, ErrNotFound
	}
	snap := s.snapshot()
	if c.expire(s.clock()) {
		if err := s.persist(); err != nil {
			s.conv = snap
			return View{}, err
		}
	}
	msgs := make([]Entry, len(c.Log))
	copy(msgs, c.Log)
	return View{ID: c.Peer, Name: c.Name, Keep: c.Keep, For: c.For, Pending: c.PendingNext, Messages: msgs}, nil
}

// NextCounter is the next outgoing counter for the conversation with peerID.
func (s *Store) NextCounter(peerID string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := canonical(peerID)
	if err != nil {
		return 0, err
	}
	c, ok := s.conv[peer]
	if !ok {
		return 0, ErrStranger
	}
	return c.SelfNext, nil
}

// CommitOutgoing appends a letter we successfully handed to the mailbox.
// The counter must be the next counter for us. Unix time does not change order.
func (s *Store) CommitOutgoing(msg seal.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if msg.Sender != s.self {
		return ErrInvalid
	}
	peer, err := canonical(msg.Recipient)
	if err != nil {
		return err
	}
	c, ok := s.conv[peer]
	if !ok {
		return ErrStranger
	}
	if msg.Counter == 0 || msg.Counter > maxCounter || msg.Counter != c.SelfNext {
		if msg.Counter != 0 && msg.Counter < c.SelfNext {
			return ErrReplay
		}
		return ErrInvalid
	}
	entry, err := entryFrom(msg)
	if err != nil {
		return err
	}
	if entry.Recipient != c.Peer {
		return ErrInvalid
	}
	snap := s.snapshot()
	if c.Keep {
		entry.Kept = s.clock().Unix()
		c.Log = append(c.Log, entry)
	}
	c.SelfNext++
	c.expire(s.clock())
	if err := s.persist(); err != nil {
		s.conv = snap
		return err
	}
	return nil
}

// Accept follows a pending successor. The conversation stays on the current
// glyph ID until this is called. A gap still has to fill before the id changes.
// The returned id is empty when the follow is recorded but the gap remains.
func (s *Store) Accept(peerID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := canonical(peerID)
	if err != nil {
		return "", err
	}
	c, ok := s.conv[peer]
	if !ok {
		return "", ErrNotFound
	}
	if c.PendingNext == "" {
		return "", ErrSuccessor
	}
	snap := s.snapshot()
	c.Follow = true
	var next string
	if len(c.Held) == 0 {
		next = c.PendingNext
		if err := s.rekey(c, next); err != nil {
			s.conv = snap
			return "", err
		}
	}
	if err := s.persist(); err != nil {
		s.conv = snap
		return "", err
	}
	return next, nil
}

// Skip consumes the peer's next counter without storing the letter.
// It applies only when that counter is the one the conversation is waiting for.
// A letter already held at the counter Skip lands on is released, or consumed
// when that letter is a successor this chat cannot follow.
func (s *Store) Skip(msg seal.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if msg.Recipient != s.self {
		return ErrRecipient
	}
	sender, err := canonical(msg.Sender)
	if err != nil {
		return ErrStranger
	}
	c, ok := s.conv[sender]
	if !ok {
		return ErrStranger
	}
	if msg.Counter == 0 || msg.Counter > maxCounter || msg.Counter != c.PeerNext {
		return ErrInvalid
	}
	snap := s.snapshot()
	delete(c.Held, c.PeerNext)
	if c.PeerNext == ^uint64(0) {
		return ErrInvalid
	}
	c.PeerNext++
	exists := func(id string) bool { return s.nextTaken(id, c) }
	if _, err := c.drainHeld(s.self, exists, s.clock().Unix()); err != nil {
		s.conv = snap
		return err
	}
	for k := range c.Held {
		if k <= c.PeerNext {
			s.conv = snap
			return ErrInvalid
		}
	}
	if c.Follow && c.PendingNext != "" && len(c.Held) == 0 {
		if err := s.rekey(c, c.PendingNext); err != nil {
			s.conv = snap
			return err
		}
	}
	if err := s.persist(); err != nil {
		s.conv = snap
		return err
	}
	return nil
}

// Ingest accepts a letter opened for this store. The sender must already be
// the current glyph ID of a conversation. A gap is held, a duplicate counter
// is dropped, and a successor from that peer rekeys the conversation without
// dropping its history. A successor from anyone else is rejected.
func (s *Store) Ingest(msg seal.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if msg.Recipient != s.self {
		return ErrRecipient
	}
	sender, err := canonical(msg.Sender)
	if err != nil {
		return ErrStranger
	}
	c, ok := s.conv[sender]
	if !ok {
		return ErrStranger
	}
	snap := s.snapshot()
	exists := func(id string) bool { return s.nextTaken(id, c) }
	next, err := c.apply(msg, s.self, exists, s.clock().Unix())
	if err != nil {
		s.conv = snap
		return err
	}
	if next != "" {
		if err := s.rekey(c, next); err != nil {
			s.conv = snap
			return err
		}
	}
	if err := s.persist(); err != nil {
		s.conv = snap
		return err
	}
	return nil
}

func (c *conv) apply(msg seal.Message, self string, exists func(string) bool, kept int64) (string, error) {
	if msg.Sender != c.Peer {
		return "", ErrStranger
	}
	if msg.Kind == seal.KindSuccessor {
		if err := seal.VerifySuccessor(msg.Sender, msg.Recipient, msg.Next, msg.NextSig); err != nil {
			return "", ErrSuccessor
		}
	}
	if msg.Counter == 0 || msg.Counter > maxCounter {
		return "", ErrInvalid
	}
	if msg.Counter < c.PeerNext {
		return "", ErrReplay
	}
	if _, dup := c.Held[msg.Counter]; dup {
		return "", ErrReplay
	}
	entry, err := entryFrom(msg)
	if err != nil {
		return "", err
	}
	if !c.Keep {
		entry.Text = ""
	}
	if msg.Counter > c.PeerNext {
		if len(c.Held) >= maxHeld {
			return "", ErrInvalid
		}
		if entry.Kind == seal.KindSuccessor {
			if err := validateSuccessor(entry.Next, self, c.Peer, exists); err != nil {
				return "", err
			}
		}
		if c.Held == nil {
			c.Held = map[uint64]Entry{}
		}
		c.Held[msg.Counter] = entry
		return "", nil
	}
	if err := c.release(entry, self, exists, kept); err != nil {
		return "", err
	}
	if _, err := c.drainHeld(self, exists, kept); err != nil {
		return "", err
	}
	if c.Follow && c.PendingNext != "" && len(c.Held) == 0 {
		return c.PendingNext, nil
	}
	return "", nil
}

func (c *conv) release(e Entry, self string, exists func(string) bool, kept int64) error {
	if e.Kind == seal.KindSuccessor {
		if err := validateSuccessor(e.Next, self, c.Peer, exists); err != nil {
			return err
		}
		if c.PendingNext != "" && c.PendingNext != e.Next {
			return ErrSuccessor
		}
		c.PendingNext = e.Next
	}
	if c.Keep {
		e.Kept = kept
		c.Log = append(c.Log, e)
	}
	if c.PeerNext == ^uint64(0) {
		return ErrInvalid
	}
	c.PeerNext++
	return nil
}

// drainHeld releases letters the conversation has caught up to.
// A successor that no longer agrees is consumed and left out of the log.
// The letter that filled the gap stays. A held counter is never left at or
// behind the counter the chat is waiting for.
func (c *conv) drainHeld(self string, exists func(string) bool, kept int64) (bool, error) {
	changed := false
	for {
		h, ok := c.Held[c.PeerNext]
		if !ok {
			return changed, nil
		}
		delete(c.Held, c.PeerNext)
		changed = true
		if err := c.release(h, self, exists, kept); err != nil {
			if errors.Is(err, ErrSuccessor) {
				if c.PeerNext == ^uint64(0) {
					return changed, ErrInvalid
				}
				c.PeerNext++
				continue
			}
			return changed, err
		}
	}
}

func (c *conv) expire(now time.Time) bool {
	if !c.Keep {
		if len(c.Log) == 0 {
			return false
		}
		c.Log = nil
		return true
	}
	if c.For <= 0 || len(c.Log) == 0 {
		return false
	}
	cutoff := now.Unix() - c.For
	kept := c.Log[:0]
	changed := false
	for _, e := range c.Log {
		if e.Kept <= 0 || e.Kept < cutoff {
			changed = true
			continue
		}
		kept = append(kept, e)
	}
	if changed {
		c.Log = kept
	}
	return changed
}

func (s *Store) expireAll() bool {
	now := s.clock()
	changed := false
	for _, c := range s.conv {
		if c.expire(now) {
			changed = true
		}
	}
	return changed
}

func (s *Store) rekey(c *conv, next string) error {
	exists := func(id string) bool {
		_, ok := s.conv[id]
		return ok
	}
	if err := validateSuccessor(next, s.self, c.Peer, exists); err != nil {
		return err
	}
	// This chat takes next. Another chat that named the same next ID keeps
	// its history and drops the pending follow, so the file stays openable.
	for _, other := range s.conv {
		if other != c && other.PendingNext == next {
			other.PendingNext = ""
			other.Follow = false
		}
	}
	old := c.Peer
	delete(s.conv, old)
	c.Peer = next
	c.PeerNext = 1
	c.Held = map[uint64]Entry{}
	c.PendingNext = ""
	c.Follow = false
	s.conv[next] = c
	return nil
}

// nextTaken reports whether id is already a chat, or another chat has named
// it as a successor. except may keep its own pending claim.
func (s *Store) nextTaken(id string, except *conv) bool {
	if _, ok := s.conv[id]; ok {
		return true
	}
	for _, c := range s.conv {
		if c == except {
			continue
		}
		if c.PendingNext == id {
			return true
		}
	}
	return false
}

func validateSuccessor(next, self, peer string, exists func(string) bool) error {
	canon, err := canonical(next)
	if err != nil || canon != next {
		return ErrSuccessor
	}
	if canon == self || canon == peer {
		return ErrSuccessor
	}
	if exists != nil && exists(canon) {
		return ErrSuccessor
	}
	return nil
}

func entryFrom(msg seal.Message) (Entry, error) {
	if msg.Counter == 0 || msg.Counter > maxCounter {
		return Entry{}, ErrInvalid
	}
	if _, err := canonical(msg.Sender); err != nil {
		return Entry{}, ErrInvalid
	}
	if _, err := canonical(msg.Recipient); err != nil {
		return Entry{}, ErrInvalid
	}
	switch msg.Kind {
	case seal.KindChat:
		if msg.Next != "" || !utf8.ValidString(msg.Text) || len(msg.Text) > maxText {
			return Entry{}, ErrInvalid
		}
	case seal.KindSuccessor:
		if msg.Text != "" {
			return Entry{}, ErrInvalid
		}
		if _, err := canonical(msg.Next); err != nil {
			return Entry{}, ErrSuccessor
		}
	default:
		return Entry{}, ErrInvalid
	}
	return Entry{
		Sender:    msg.Sender,
		Recipient: msg.Recipient,
		Kind:      msg.Kind,
		Counter:   msg.Counter,
		Unix:      msg.Unix,
		Text:      msg.Text,
		Next:      msg.Next,
	}, nil
}

func canonical(id string) (string, error) {
	pub, err := identity.Parse(id)
	if err != nil {
		return "", err
	}
	out, err := identity.Format(pub)
	if err != nil {
		return "", err
	}
	if out != id {
		return "", identity.ErrInvalidID
	}
	return out, nil
}

func checkName(name string) error {
	if !utf8.ValidString(name) || len(name) > maxName {
		return ErrInvalid
	}
	return nil
}

func (s *Store) snapshot() map[string]*conv {
	cp := make(map[string]*conv, len(s.conv))
	for k, c := range s.conv {
		cp[k] = c.clone()
	}
	return cp
}

func (c *conv) clone() *conv {
	if c == nil {
		return nil
	}
	n := *c
	n.Log = append([]Entry(nil), c.Log...)
	n.Held = make(map[uint64]Entry, len(c.Held))
	for k, v := range c.Held {
		n.Held[k] = v
	}
	return &n
}

func (s *Store) path() string { return filepath.Join(s.dir, "store.json") }

func (s *Store) persist() error {
	raw, err := json.MarshalIndent(s.toDisk(), "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeAtomic(s.path(), raw)
}

func (s *Store) load() error {
	path := s.path()
	if b, err := os.ReadFile(path + ".tmp"); err == nil {
		if convs, _, err := s.parseDisk(bytes.TrimSpace(b)); err == nil {
			s.conv = convs
			if _, err := s.repairHeld(); err != nil {
				return err
			}
			if _, err := s.finishFollow(); err != nil {
				return err
			}
			if err := s.persist(); err != nil {
				return err
			}
			_ = os.Remove(path + ".tmp")
			return nil
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	convs, stripped, err := s.parseDisk(bytes.TrimSpace(b))
	if err != nil {
		return err
	}
	s.conv = convs
	repaired, err := s.repairHeld()
	if err != nil {
		return err
	}
	changed, err := s.finishFollow()
	if err != nil {
		return err
	}
	if stripped || repaired || changed {
		return s.persist()
	}
	return nil
}

// repairHeld opens a store whose hold was left on the counter the chat is
// waiting for. One damaged conversation does not reject the rest of the file.
// A held letter behind that counter is dropped. The letter at that counter is
// delivered, or consumed when it is a successor this chat cannot follow.
func (s *Store) repairHeld() (bool, error) {
	kept := s.clock().Unix()
	changed := false
	for _, c := range s.conv {
		for k := range c.Held {
			if k < c.PeerNext {
				delete(c.Held, k)
				changed = true
			}
		}
		exists := func(id string) bool { return s.nextTaken(id, c) }
		drained, err := c.drainHeld(s.self, exists, kept)
		if err != nil {
			return false, err
		}
		if drained {
			changed = true
		}
	}
	return changed, nil
}

func (s *Store) finishFollow() (bool, error) {
	var ready []*conv
	for _, c := range s.conv {
		if c.Follow && c.PendingNext != "" && len(c.Held) == 0 {
			ready = append(ready, c)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].Peer < ready[j].Peer })
	changed := false
	for _, c := range ready {
		if c.PendingNext == "" || !c.Follow {
			continue
		}
		if err := s.rekey(c, c.PendingNext); err != nil {
			// One chat already took this ID. Drop the follow and keep the store.
			c.PendingNext = ""
			c.Follow = false
			changed = true
			continue
		}
		changed = true
	}
	return changed, nil
}

type diskFile struct {
	V     int        `json:"v"`
	Self  string     `json:"self"`
	Convs []diskConv `json:"convs"`
}

type diskConv struct {
	Peer        string      `json:"peer"`
	Name        string      `json:"name,omitempty"`
	Record      *bool       `json:"record,omitempty"`
	ForSec      int64       `json:"for_sec,omitempty"`
	SelfNext    uint64      `json:"self_next"`
	PeerNext    uint64      `json:"peer_next"`
	PendingNext string      `json:"pending_next,omitempty"`
	Follow      bool        `json:"follow,omitempty"`
	Reach       string      `json:"reach,omitempty"`
	Log         []diskEntry `json:"log"`
	Held        []diskEntry `json:"held,omitempty"`
}

type diskEntry struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Kind      string `json:"kind"`
	Counter   uint64 `json:"counter"`
	Unix      int64  `json:"unix"`
	Kept      int64  `json:"kept,omitempty"`
	Text      string `json:"text,omitempty"`
	Next      string `json:"next,omitempty"`
}

func (s *Store) toDisk() diskFile {
	ids := make([]string, 0, len(s.conv))
	for id := range s.conv {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := diskFile{V: diskV, Self: s.self, Convs: make([]diskConv, 0, len(ids))}
	for _, id := range ids {
		c := s.conv[id]
		var record *bool
		if !c.Keep {
			record = boolPtr(false)
		}
		dc := diskConv{
			Peer:        c.Peer,
			Name:        c.Name,
			Record:      record,
			ForSec:      c.For,
			SelfNext:    c.SelfNext,
			PeerNext:    c.PeerNext,
			PendingNext: c.PendingNext,
			Follow:      c.Follow,
			Reach:       c.Reach,
			Log:         make([]diskEntry, len(c.Log)),
		}
		for i, e := range c.Log {
			dc.Log[i] = e.toDisk()
		}
		heldKeys := make([]uint64, 0, len(c.Held))
		for k := range c.Held {
			heldKeys = append(heldKeys, k)
		}
		sort.Slice(heldKeys, func(i, j int) bool { return heldKeys[i] < heldKeys[j] })
		for _, k := range heldKeys {
			dc.Held = append(dc.Held, c.Held[k].toDisk())
		}
		out.Convs = append(out.Convs, dc)
	}
	return out
}

func (e Entry) toDisk() diskEntry {
	kind := "chat"
	if e.Kind == seal.KindSuccessor {
		kind = "successor"
	}
	return diskEntry{
		Sender: e.Sender, Recipient: e.Recipient, Kind: kind,
		Counter: e.Counter, Unix: e.Unix, Kept: e.Kept, Text: e.Text, Next: e.Next,
	}
}

func boolPtr(v bool) *bool { return &v }

func (s *Store) parseDisk(raw []byte) (map[string]*conv, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d diskFile
	if err := dec.Decode(&d); err != nil {
		return nil, false, ErrInvalid
	}
	if dec.InputOffset() != int64(len(raw)) || (d.V != 1 && d.V != diskV) || d.Self != s.self {
		return nil, false, ErrInvalid
	}
	out := make(map[string]*conv, len(d.Convs))
	stripped := false
	for _, dc := range d.Convs {
		peer, err := canonical(dc.Peer)
		if err != nil || peer != dc.Peer || peer == s.self {
			return nil, false, ErrInvalid
		}
		if _, dup := out[peer]; dup {
			return nil, false, ErrInvalid
		}
		if err := checkName(dc.Name); err != nil || dc.SelfNext == 0 || dc.PeerNext == 0 {
			return nil, false, ErrInvalid
		}
		keep := true
		if dc.Record != nil {
			keep = *dc.Record
		}
		if dc.ForSec < 0 || dc.ForSec > maxForSec || (!keep && dc.ForSec != 0) {
			return nil, false, ErrInvalid
		}
		if dc.PendingNext != "" {
			if _, err := canonical(dc.PendingNext); err != nil || dc.PendingNext == peer || dc.PendingNext == s.self {
				return nil, false, ErrInvalid
			}
		}
		if dc.Follow && dc.PendingNext == "" {
			return nil, false, ErrInvalid
		}
		reach := dc.Reach
		if strings.ContainsAny(reach, " \t\r\n") || len(reach) > 253 {
			reach = ""
			stripped = true
		}
		c := &conv{
			Peer: peer, Name: dc.Name, Keep: keep, For: dc.ForSec,
			SelfNext: dc.SelfNext, PeerNext: dc.PeerNext,
			PendingNext: dc.PendingNext, Follow: dc.Follow, Reach: reach, Held: map[uint64]Entry{},
		}
		for _, de := range dc.Log {
			e, err := de.entry()
			if err != nil {
				return nil, false, err
			}
			if e.Sender == peer && e.Counter >= c.PeerNext {
				return nil, false, ErrInvalid
			}
			if e.Sender == s.self && e.Counter >= c.SelfNext {
				return nil, false, ErrInvalid
			}
			if !keep && e.Text != "" {
				stripped = true
			}
			c.Log = append(c.Log, e)
		}
		if !keep {
			c.Log = nil
		}
		for _, de := range dc.Held {
			e, err := de.entry()
			if err != nil {
				return nil, false, err
			}
			if e.Sender != peer {
				return nil, false, ErrInvalid
			}
			if e.Counter < c.PeerNext {
				stripped = true
				continue
			}
			if _, dup := c.Held[e.Counter]; dup {
				return nil, false, ErrInvalid
			}
			if !keep && e.Text != "" {
				e.Text = ""
				stripped = true
			}
			c.Held[e.Counter] = e
		}
		out[peer] = c
	}
	for _, c := range out {
		if c.PendingNext == "" {
			continue
		}
		if _, ok := out[c.PendingNext]; !ok {
			continue
		}
		// The next ID is already a chat. Drop the pending follow so this
		// file still opens, and keep both histories.
		c.PendingNext = ""
		c.Follow = false
		stripped = true
	}
	return out, stripped, nil
}

func (d diskEntry) entry() (Entry, error) {
	var kind seal.Kind
	switch d.Kind {
	case "chat":
		kind = seal.KindChat
	case "successor":
		kind = seal.KindSuccessor
	default:
		return Entry{}, ErrInvalid
	}
	e := Entry{
		Sender: d.Sender, Recipient: d.Recipient, Kind: kind,
		Counter: d.Counter, Unix: d.Unix, Kept: d.Kept, Text: d.Text, Next: d.Next,
	}
	checked, err := entryFrom(seal.Message{
		Sender: e.Sender, Recipient: e.Recipient, Kind: e.Kind,
		Counter: e.Counter, Unix: e.Unix, Text: e.Text, Next: e.Next,
	})
	if err != nil {
		return Entry{}, err
	}
	checked.Kept = e.Kept
	return checked, nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(tmp, path)
}
