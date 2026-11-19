package app

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"glyph/identity"

	mbox "glyph-mailbox"
)

func TestMain(m *testing.M) {
	os.Unsetenv("GLYPH_MAILBOX")
	os.Unsetenv("GLYPH_MAILBOX_KEY")
	os.Unsetenv("GLYPH_HOME")
	os.Unsetenv("GLYPH_LISTEN")
	os.Setenv("GLYPH_DIRECT", "127.0.0.1:0")
	os.Exit(m.Run())
}

func TestNormalizeAcceptsFullIDOnly(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := normalizeID(strings.ToUpper(strings.TrimPrefix(id.ID(), "glyph:")))
	if err != nil || got != id.ID() {
		t.Fatalf("bare id %q %v", got, err)
	}
	got, err = normalizeID("  " + id.ID() + "\n")
	if err != nil || got != id.ID() {
		t.Fatalf("spaced id %q %v", got, err)
	}
	if _, err := normalizeID(id.ID()[:len(id.ID())-2]); err == nil {
		t.Fatal("prefix was accepted")
	}
	if _, err := normalizeID("glyph:"); err == nil {
		t.Fatal("empty id was accepted")
	}
}

func TestExchangeAndQuietFailures(t *testing.T) {
	owner := openTestApp(t)
	friend := openTestApp(t)
	if !owner.pullState().Direct || friend.node == nil {
		t.Fatal("direct listener did not start")
	}
	if !owner.OpenChat(friend.id.ID()) {
		t.Fatal("open friend")
	}
	if owner.OpenChat("glyph:abcd") || owner.OpenChat(owner.id.ID()) {
		t.Fatal("bad id opened a chat")
	}
	if !friend.OpenChat(strings.ToUpper(strings.TrimPrefix(owner.id.ID(), "glyph:"))) {
		t.Fatal("friend open")
	}
	if owner.Send(friend.id.ID(), "too-soon") {
		t.Fatal("sent before a reachable address was given")
	}
	if err := owner.node.SetReach(friend.id.ID(), friend.node.Addr()); err != nil {
		t.Fatal(err)
	}
	if err := friend.node.SetReach(owner.id.ID(), owner.node.Addr()); err != nil {
		t.Fatal(err)
	}

	const marker = "glyph-window-marker-9f3a2c"
	if !owner.Send(friend.id.ID(), marker) {
		t.Fatal("send")
	}
	if owner.Send(friend.id.ID(), "   ") {
		t.Fatal("blank send")
	}
	view := friend.pullState()
	if len(view.Chats) != 1 || len(view.Chats[0].Messages) != 1 || view.Chats[0].Messages[0].Text != marker || view.Chats[0].Messages[0].Out {
		t.Fatalf("friend view %#v", view.Chats)
	}
	if err := filepath.Walk(owner.home, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.Contains(path, "transcript") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(marker)) {
			return os.ErrExist
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if !friend.Send(owner.id.ID(), "reply") {
		t.Fatal("reply")
	}
	owner.mu.Lock()
	owner.touchLocked()
	owner.mu.Unlock()
	back := owner.pullState()
	if len(back.Chats[0].Messages) != 2 || back.Chats[0].Messages[1].Text != "reply" {
		t.Fatalf("owner view %#v", back.Chats)
	}

	if !owner.SetRecord(friend.id.ID(), "off") {
		t.Fatal("record off")
	}
	if !owner.Send(friend.id.ID(), "not-kept") {
		t.Fatal("send while not keeping")
	}
	kept := owner.pullState()
	if len(kept.Chats) != 1 || kept.Chats[0].Keep != "off" || len(kept.Chats[0].Messages) != 0 {
		t.Fatalf("owner kept letters after record off %#v", kept.Chats)
	}
	friend.mu.Lock()
	friend.touchLocked()
	friend.mu.Unlock()
	got := friend.pullState()
	if len(got.Chats[0].Messages) != 3 || got.Chats[0].Messages[2].Text != "not-kept" {
		t.Fatalf("friend missed an unkept letter %#v", got.Chats[0].Messages)
	}
	if !owner.RemoveFriend(friend.id.ID()) {
		t.Fatal("remove friend")
	}
	if friend.Send(owner.id.ID(), "after-remove") {
		t.Fatal("removed friend was still allowed to send")
	}
}

func TestForgedAnnouncementDoesNotDeliver(t *testing.T) {
	owner := openTestApp(t)
	friend := openTestApp(t)
	stranger := openTestApp(t)
	if !owner.OpenChat(friend.id.ID()) || !friend.OpenChat(owner.id.ID()) || !stranger.OpenChat(owner.id.ID()) {
		t.Fatal("open")
	}
	if err := stranger.node.SetReach(owner.id.ID(), owner.node.Addr()); err != nil {
		t.Fatal(err)
	}
	if stranger.Send(owner.id.ID(), "intruder") {
		t.Fatal("stranger delivered a letter")
	}
	if len(owner.pullState().Chats) != 1 || len(owner.pullState().Chats[0].Messages) != 0 {
		t.Fatal("owner stored a stranger's letter")
	}
}

func TestStaleMailboxStaysUnset(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return
		}
		raw, err := json.Marshal(map[string]any{"v": mbox.Protocol() + 1, "type": "hello", "nonce": nonce})
		if err != nil {
			return
		}
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))
		_, _ = c.Write(hdr[:])
		_, _ = c.Write(raw)
	}()
	a := openTestApp(t)
	a.candidates = []string{ln.Addr().String()}
	a.bindAddr = ln.Addr().String()
	called := false
	a.host = func(string, string, string) error {
		called = true
		return nil
	}
	if a.Setup() || called || a.pullState().Mailbox != "none" {
		t.Fatal("stale mailbox was treated as online")
	}
}

func TestWindowPage(t *testing.T) {
	a := openTestApp(t)
	addr, err := a.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	token := a.token
	barePage, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	barePage.Body.Close()
	if barePage.StatusCode != http.StatusNotFound {
		t.Fatalf("untokened page %d", barePage.StatusCode)
	}
	res, err := http.Get("http://" + addr + "/?t=" + token)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("page %d", res.StatusCode)
	}
	page := string(body)
	for _, want := range []string{"you are:", "glyph id", "host:port", "auto update from GitHub", "no tpm implementation"} {
		if !strings.Contains(page, want) {
			t.Fatalf("page missing %q", want)
		}
	}
	for _, banned := range []string{"Mira", "Sam", "{{TOKEN}}", "https://", "http://"} {
		if strings.Contains(page, banned) {
			t.Fatalf("page contains %q", banned)
		}
	}
	if strings.Contains(page, token) {
		t.Fatal("page embeds the token")
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/api/open", strings.NewReader(`{"id":"glyph:nope"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Glyph-Token", token)
	req.Header.Set("Content-Type", "application/json")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var out resultJSON
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.OK || len(out.State.Chats) != 0 || out.State.ID != a.id.ID() {
		t.Fatalf("bad id %#v", out)
	}
	bare, err := http.NewRequest(http.MethodGet, "http://"+addr+"/api/state", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err = http.DefaultClient.Do(bare)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("untokened state %d", res.StatusCode)
	}
}

func openTestApp(t *testing.T) *App {
	t.Helper()
	a, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	a.candidates = []string{}
	return a
}

func inprocHost(t *testing.T) func(dir, owner, addr string) error {
	t.Helper()
	var mu sync.Mutex
	var servers []*mbox.Server
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range servers {
			s.Close()
		}
	})
	return func(dir, owner, addr string) error {
		s, err := mbox.New(dir, owner)
		if err != nil {
			return err
		}
		if _, err := s.Start(addr); err != nil {
			s.Close()
			return err
		}
		mu.Lock()
		servers = append(servers, s)
		mu.Unlock()
		return nil
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func walkContains(root string, needle []byte) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, needle) {
			return os.ErrExist
		}
		return nil
	})
}
