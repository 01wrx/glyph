package transcript

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"glyph/identity"
	"glyph/seal"
)

func TestDeliverInCounterOrderNotUnixTime(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitOutgoing(chat(self.ID(), alice.ID(), 1, 10, "me")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 1, "them")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 2, 0, "later")); err != nil {
		t.Fatal(err)
	}
	msgs := mustView(t, s, alice.ID()).Messages
	if len(msgs) != 3 {
		t.Fatalf("messages %#v", msgs)
	}
	if msgs[0].Text != "me" || msgs[1].Text != "them" || msgs[2].Text != "later" {
		t.Fatalf("order followed unix time: %#v", msgs)
	}
	if msgs[0].Unix != 10 || msgs[1].Unix != 1 || msgs[2].Unix != 0 {
		t.Fatalf("unix changed: %#v", msgs)
	}
}

func TestHoldGapUntilCounterArrives(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 2, 1, "second")); err != nil {
		t.Fatal(err)
	}
	if got := mustView(t, s, alice.ID()).Messages; len(got) != 0 {
		t.Fatalf("gap was delivered early: %#v", got)
	}
	reopened, err := Open(s.dir, self.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got := mustView(t, reopened, alice.ID()).Messages; len(got) != 0 {
		t.Fatalf("reopen delivered a gap: %#v", got)
	}
	if err := reopened.Ingest(chat(alice.ID(), self.ID(), 1, 5000, "first")); err != nil {
		t.Fatal(err)
	}
	msgs := mustView(t, reopened, alice.ID()).Messages
	if len(msgs) != 2 || msgs[0].Counter != 1 || msgs[1].Counter != 2 {
		t.Fatalf("gap fill order %#v", msgs)
	}
	if msgs[0].Unix != 5000 || msgs[1].Unix != 1 || msgs[0].Text != "first" || msgs[1].Text != "second" {
		t.Fatalf("held letter changed: %#v", msgs)
	}
}

func TestDropDuplicateCounter(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 2, 1, "held")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 2, 9, "other")); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate hold err=%v", err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 8, "first")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 100, "replay")); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate delivered err=%v", err)
	}
	msgs := mustView(t, s, alice.ID()).Messages
	if len(msgs) != 2 || msgs[0].Text != "first" || msgs[1].Text != "held" {
		t.Fatalf("duplicate changed the transcript: %#v", msgs)
	}
}

func TestRejectReplay(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	msg := chat(alice.ID(), self.ID(), 1, 4, "once")
	if err := s.Ingest(msg); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(msg); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay err=%v", err)
	}
	reopened, err := Open(s.dir, self.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Ingest(msg); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after reopen err=%v", err)
	}
	if _, err := Open(s.dir, alice.ID()); err == nil {
		t.Fatal("store opened as a different glyph id")
	}
	msgs := mustView(t, reopened, alice.ID()).Messages
	if len(msgs) != 1 || msgs[0].Text != "once" {
		t.Fatalf("replay recorded: %#v", msgs)
	}
}

func TestSuccessorRekeyKeepsHistory(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	alice2 := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 100, "kept")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(succ(t, alice, self, alice2, 2, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Conversation(alice2.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatal("followed the new id before it was accepted")
	}
	if _, err := s.Accept(alice.ID()); err != nil {
		t.Fatal(err)
	}
	view := mustView(t, s, alice2.ID())
	if _, err := s.Conversation(alice.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatal("old id still addresses the conversation")
	}
	if view.Name != "Ada" || view.ID != alice2.ID() {
		t.Fatalf("view %+v", view)
	}
	if len(view.Messages) != 2 || view.Messages[0].Text != "kept" || view.Messages[1].Next != alice2.ID() {
		t.Fatalf("history lost: %#v", view.Messages)
	}
	reopened, err := Open(s.dir, self.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Conversation(alice.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatal("reopen restored the old id")
	}
	if err := reopened.Ingest(chat(alice.ID(), self.ID(), 3, 1, "old-key")); !errors.Is(err, ErrStranger) {
		t.Fatalf("old key accepted after successor: %v", err)
	}
	if err := reopened.Ingest(chat(alice2.ID(), self.ID(), 1, 2, "new-key")); err != nil {
		t.Fatal(err)
	}
	msgs := mustView(t, reopened, alice2.ID()).Messages
	if len(msgs) != 3 || msgs[2].Text != "new-key" || msgs[2].Counter != 1 {
		t.Fatalf("new id did not continue the chat: %#v", msgs)
	}
}

func TestSuccessorWaitsForEarlierCounter(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	alice2 := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(succ(t, alice, self, alice2, 2, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Conversation(alice2.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatal("successor rekeyed before the gap filled")
	}
	if got := mustView(t, s, alice.ID()).Messages; len(got) != 0 {
		t.Fatalf("held successor visible: %#v", got)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 50, "first")); err != nil {
		t.Fatal(err)
	}
	waiting := mustView(t, s, alice.ID())
	if waiting.Pending != alice2.ID() || len(waiting.Messages) != 2 || waiting.Messages[0].Counter != 1 || waiting.Messages[1].Kind != seal.KindSuccessor {
		t.Fatalf("gap filled into %#v", waiting)
	}
	if _, err := s.Accept(alice.ID()); err != nil {
		t.Fatal(err)
	}
	view := mustView(t, s, alice2.ID())
	if len(view.Messages) != 2 || view.Messages[0].Counter != 1 || view.Messages[1].Kind != seal.KindSuccessor {
		t.Fatalf("order %#v", view.Messages)
	}
}

func TestSuccessorFromAnyoneElseRejected(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	eve := mustID(t)
	eve2 := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 1, "hi")); err != nil {
		t.Fatal(err)
	}
	err := s.Ingest(seal.Message{
		Sender: eve.ID(), Recipient: self.ID(), Kind: seal.KindSuccessor,
		Counter: 1, Unix: 1, Next: eve2.ID(),
	})
	if !errors.Is(err, ErrStranger) {
		t.Fatalf("stranger successor err=%v", err)
	}
	if mustView(t, s, alice.ID()).ID != alice.ID() {
		t.Fatal("alice moved")
	}
	if _, err := s.Conversation(eve2.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatal("stranger successor created an address")
	}
	if err := s.Add(eve.ID(), ""); err != nil {
		t.Fatal(err)
	}
	err = s.Ingest(succ(t, eve, self, alice, 1, 1))
	if !errors.Is(err, ErrSuccessor) {
		t.Fatalf("colliding successor err=%v", err)
	}
	if got := mustView(t, s, alice.ID()); len(got.Messages) != 1 || got.Messages[0].Text != "hi" {
		t.Fatalf("alice chat changed: %+v", got)
	}
	if got := mustView(t, s, eve.ID()); len(got.Messages) != 0 || got.ID != eve.ID() {
		t.Fatalf("eve chat changed: %+v", got)
	}
}

func TestNewIDWithoutSuccessorIsStranger(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	alice2 := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 1, "stay")); err != nil {
		t.Fatal(err)
	}
	err := s.Ingest(chat(alice2.ID(), self.ID(), 1, 1, "new person"))
	if !errors.Is(err, ErrStranger) {
		t.Fatalf("err=%v", err)
	}
	view := mustView(t, s, alice.ID())
	if len(view.Messages) != 1 || view.Messages[0].Text != "stay" || view.ID != alice.ID() {
		t.Fatalf("old chat changed: %+v", view)
	}
	if _, err := s.Conversation(alice2.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatal("new id was linked without a successor")
	}
}

func TestCounterIsPerConversation(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	bob := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(bob.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 9, "a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(bob.ID(), self.ID(), 1, 1, "b")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 2, 1, "a2")); err != nil {
		t.Fatal(err)
	}
	a := mustView(t, s, alice.ID()).Messages
	b := mustView(t, s, bob.ID()).Messages
	if len(a) != 2 || a[0].Text != "a" || a[1].Text != "a2" || len(b) != 1 || b[0].Text != "b" {
		t.Fatalf("counters leaked across chats alice=%#v bob=%#v", a, b)
	}
}

func TestDisplayNameIsLocalLabel(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	bob := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(bob.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetName(alice.ID(), bob.ID()); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 1, "from alice")); err != nil {
		t.Fatal(err)
	}
	byName := mustView(t, s, bob.ID())
	if len(byName.Messages) != 0 || byName.ID != bob.ID() {
		t.Fatalf("name was used as an address: %+v", byName)
	}
	labeled := mustView(t, s, alice.ID())
	if labeled.Name != bob.ID() || len(labeled.Messages) != 1 || labeled.Messages[0].Text != "from alice" {
		t.Fatalf("label broke the id key: %+v", labeled)
	}
	if _, err := s.Conversation("Ada"); err == nil {
		t.Fatal("display name opened a conversation")
	}
	if _, err := s.Conversation(alice.ID()[:len(alice.ID())-1]); err == nil {
		t.Fatal("prefix opened a conversation")
	}
	if err := s.Add(self.ID(), ""); err == nil {
		t.Fatal("added self")
	}
}

func TestRecordOffKeepsCountersNotText(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecord(alice.ID(), false, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitOutgoing(chat(self.ID(), alice.ID(), 1, 10, "secret-out")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 1, "secret-in")); err != nil {
		t.Fatal(err)
	}
	view := mustView(t, s, alice.ID())
	if view.Keep || len(view.Messages) != 0 {
		t.Fatalf("record kept %#v", view)
	}
	n, err := s.NextCounter(alice.ID())
	if err != nil || n != 2 {
		t.Fatalf("counter %d %v", n, err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 1, "secret-in")); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay err %v", err)
	}
	raw, err := os.ReadFile(s.path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-out")) || bytes.Contains(raw, []byte("secret-in")) {
		t.Fatal("record off left letter text on disk")
	}
}

func TestRecordOffStillFillsAGapThenDropsIt(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecord(alice.ID(), false, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 2, 1, "gap-two")); err != nil {
		t.Fatal(err)
	}
	held, err := os.ReadFile(s.path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(held, []byte("gap-two")) {
		t.Fatal("held letter was stored while record is off")
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 1, 1, "gap-one")); err != nil {
		t.Fatal(err)
	}
	if got := mustView(t, s, alice.ID()).Messages; len(got) != 0 {
		t.Fatalf("unordered mail became a record: %#v", got)
	}
	raw, err := os.ReadFile(s.path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("gap-one")) || bytes.Contains(raw, []byte("gap-two")) {
		t.Fatal("filled gap stayed on disk")
	}
}

func TestRecordExpiresByLocalTime(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	s := mustStore(t, self)
	start := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return start }
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecord(alice.ID(), true, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitOutgoing(chat(self.ID(), alice.ID(), 1, 1, "old-letter")); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return start.Add(11 * time.Second) }
	view := mustView(t, s, alice.ID())
	if !view.Keep || view.For != 10 || len(view.Messages) != 0 {
		t.Fatalf("expired %#v", view)
	}
	raw, err := os.ReadFile(s.path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("old-letter")) {
		t.Fatal("expired letter stayed on disk")
	}
}

func TestRecordRejectsBadDuration(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecord(alice.ID(), true, -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative err %v", err)
	}
	if err := s.SetRecord(alice.ID(), true, maxForSec+1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("huge err %v", err)
	}
	view := mustView(t, s, alice.ID())
	if !view.Keep || view.For != 0 {
		t.Fatalf("rejected change stuck %#v", view)
	}
}

func TestListSkipsHeldAndSortsByKept(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	bob := mustID(t)
	s := mustStore(t, self)
	start := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return start }
	if err := s.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(bob.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 2, 9, "held-letter")); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitOutgoing(chat(self.ID(), bob.ID(), 1, 1, "to-bob")); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return start.Add(time.Minute) }
	if err := s.CommitOutgoing(chat(self.ID(), alice.ID(), 1, 2, "to-ada")); err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != alice.ID() || list[1].ID != bob.ID() {
		t.Fatalf("order %#v", list)
	}
	if list[0].Name != "Ada" || list[0].Last != "to-ada" || list[0].Kept != start.Add(time.Minute).Unix() {
		t.Fatalf("ada %#v", list[0])
	}
	if strings.Contains(list[0].Last, "held") || list[1].Last != "to-bob" {
		t.Fatalf("held letter leaked %#v", list)
	}
}

func TestConflictingHeldSuccessorKeepsTheGap(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	k1 := mustID(t)
	k2 := mustID(t)
	other := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(other.ID(), "Zoe"); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitOutgoing(chat(self.ID(), other.ID(), 1, 1, "other-chat")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(succ(t, alice, self, k1, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(succ(t, alice, self, k2, 3, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 2, 1, "real-letter")); err != nil {
		t.Fatal(err)
	}
	view := mustView(t, s, alice.ID())
	if view.Pending != k1.ID() || len(view.Messages) != 2 || view.Messages[1].Text != "real-letter" {
		t.Fatalf("gap letter lost: %+v", view)
	}
	for _, m := range view.Messages {
		if m.Next == k2.ID() {
			t.Fatal("conflicting successor was stored")
		}
	}
	if s.conv[alice.ID()].PeerNext != 4 {
		t.Fatalf("peer counter %d", s.conv[alice.ID()].PeerNext)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 4, 1, "after")); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.dir, self.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got := mustView(t, reopened, other.ID()).Messages; len(got) != 1 || got[0].Text != "other-chat" {
		t.Fatalf("other chat %+v", got)
	}
	if got := mustView(t, reopened, alice.ID()).Messages; len(got) != 3 || got[2].Text != "after" {
		t.Fatalf("reopened alice %+v", got)
	}
}

func TestSuccessorPairOutOfOrderDoesNotBrick(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	k1 := mustID(t)
	k2 := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(succ(t, alice, self, k2, 2, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(succ(t, alice, self, k1, 1, 1)); err != nil {
		t.Fatal(err)
	}
	view := mustView(t, s, alice.ID())
	if view.Pending != k1.ID() || len(view.Messages) != 1 || view.Messages[0].Next != k1.ID() {
		t.Fatalf("first successor lost: %+v", view)
	}
	if _, err := Open(s.dir, self.ID()); err != nil {
		t.Fatal(err)
	}
}

func TestSkipReleasesTheHoldItLandsOn(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	other := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(other.ID(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(chat(alice.ID(), self.ID(), 2, 1, "held-chat")); err != nil {
		t.Fatal(err)
	}
	bad := succ(t, alice, self, other, 1, 1)
	if err := s.Ingest(bad); !errors.Is(err, ErrSuccessor) {
		t.Fatalf("colliding successor err=%v", err)
	}
	if err := s.Skip(bad); err != nil {
		t.Fatal(err)
	}
	view := mustView(t, s, alice.ID())
	if len(view.Messages) != 1 || view.Messages[0].Text != "held-chat" || view.Pending != "" {
		t.Fatalf("held chat was not released: %+v", view)
	}
	if _, err := Open(s.dir, self.ID()); err != nil {
		t.Fatal(err)
	}
}

func TestDamagedHoldOpensTheRestOfTheStore(t *testing.T) {
	self := mustID(t)
	alice := mustID(t)
	zoe := mustID(t)
	k1 := mustID(t)
	k2 := mustID(t)
	s := mustStore(t, self)
	if err := s.Add(alice.ID(), "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(zoe.ID(), "Zoe"); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitOutgoing(chat(self.ID(), zoe.ID(), 1, 1, "other-chat")); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(succ(t, alice, self, k1, 1, 1)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.path())
	if err != nil {
		t.Fatal(err)
	}
	var disk diskFile
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	for i := range disk.Convs {
		if disk.Convs[i].Peer != alice.ID() {
			continue
		}
		disk.Convs[i].PeerNext = 2
		disk.Convs[i].Held = []diskEntry{
			{Sender: alice.ID(), Recipient: self.ID(), Kind: "chat", Counter: 1, Unix: 1, Text: "stale"},
			{Sender: alice.ID(), Recipient: self.ID(), Kind: "chat", Counter: 2, Unix: 2, Text: "caught-up"},
			{Sender: alice.ID(), Recipient: self.ID(), Kind: "successor", Counter: 3, Unix: 3, Next: k2.ID()},
		}
	}
	out, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path(), append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.dir, self.ID())
	if err != nil {
		t.Fatal(err)
	}
	aliceView := mustView(t, reopened, alice.ID())
	if len(aliceView.Messages) != 2 || aliceView.Messages[1].Text != "caught-up" || aliceView.Pending != k1.ID() {
		t.Fatalf("repaired alice %+v", aliceView)
	}
	for _, m := range aliceView.Messages {
		if m.Next == k2.ID() {
			t.Fatal("conflicting successor was stored")
		}
	}
	zoeView := mustView(t, reopened, zoe.ID())
	if len(zoeView.Messages) != 1 || zoeView.Messages[0].Text != "other-chat" {
		t.Fatalf("other chat %+v", zoeView)
	}
	if _, err := Open(reopened.dir, self.ID()); err != nil {
		t.Fatal(err)
	}
}

func succ(t *testing.T, sender, recipient, next *identity.Identity, n uint64, unix int64) seal.Message {
	t.Helper()
	sig, err := seal.SignSuccessor(next.Private(), sender.ID(), recipient.ID(), next.ID())
	if err != nil {
		t.Fatal(err)
	}
	return seal.Message{
		Sender: sender.ID(), Recipient: recipient.ID(), Kind: seal.KindSuccessor,
		Counter: n, Unix: unix, Next: next.ID(), NextSig: sig,
	}
}

func chat(sender, recipient string, n uint64, unix int64, text string) seal.Message {
	return seal.Message{
		Sender: sender, Recipient: recipient, Kind: seal.KindChat,
		Counter: n, Unix: unix, Text: text,
	}
}

func mustID(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustStore(t *testing.T, self *identity.Identity) *Store {
	t.Helper()
	s, err := Open(t.TempDir(), self.ID())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustView(t *testing.T, s *Store, id string) View {
	t.Helper()
	v, err := s.Conversation(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
