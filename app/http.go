package app

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type stateJSON struct {
	Name       string     `json:"name"`
	ID         string     `json:"id"`
	Theme      string     `json:"theme"`
	AutoUpdate bool       `json:"autoUpdate"`
	Network     string     `json:"network"`
	Mailbox     string     `json:"mailbox"`
	Direct      bool       `json:"direct"`
	Listen      string     `json:"listen,omitempty"`
	MailboxAddr string     `json:"mailboxAddr,omitempty"`
	MailboxKey  string     `json:"mailboxKey,omitempty"`
	Open       string     `json:"open"`
	Chats      []chatJSON `json:"chats"`
}

type chatJSON struct {
	ID       string    `json:"id"`
	Label    string    `json:"label"`
	Preview  string    `json:"preview"`
	Unix     int64     `json:"unix"`
	Keep     string    `json:"keep"`
	Pending  string    `json:"pending,omitempty"`
	Messages []msgJSON `json:"messages"`
}

type msgJSON struct {
	Out  bool   `json:"out"`
	Text string `json:"text"`
	Unix int64  `json:"unix"`
	Kind string `json:"kind"`
}

type resultJSON struct {
	OK    bool      `json:"ok"`
	State stateJSON `json:"state"`
}

// Listen serves the window on a loopback address and returns that address.
func (a *App) Listen(addr string) (string, error) {
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:0"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if !loopbackHost(host) {
		return "", errors.New("glyph: refusing non-loopback")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	srv := &http.Server{
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	a.mu.Lock()
	a.srv = srv
	a.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), nil
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.servePage)
	mux.HandleFunc("GET /api/state", a.serveState)
	mux.HandleFunc("POST /api/open", a.serveOpen)
	mux.HandleFunc("POST /api/send", a.serveSend)
	mux.HandleFunc("POST /api/name", a.serveName)
	mux.HandleFunc("POST /api/theme", a.serveTheme)
	mux.HandleFunc("POST /api/update", a.serveUpdate)
	mux.HandleFunc("POST /api/setup", a.serveSetup)
	mux.HandleFunc("POST /api/join", a.serveJoin)
	mux.HandleFunc("POST /api/record", a.serveRecord)
	mux.HandleFunc("POST /api/accept", a.serveAccept)
	mux.HandleFunc("POST /api/remove", a.serveRemove)
	mux.HandleFunc("POST /api/refresh", a.serveRefresh)
	mux.HandleFunc("POST /api/select", a.serveSelect)
	return mux
}

func (a *App) servePage(w http.ResponseWriter, r *http.Request) {
	if !a.allow(r) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
	_, _ = w.Write(indexHTML)
}

func (a *App) serveState(w http.ResponseWriter, r *http.Request) {
	if !a.allow(r) {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, a.pullState())
}

func (a *App) serveOpen(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID    string `json:"id"`
		Reach string `json:"reach"`
	}
	a.serveBool(w, r, &body, func() bool {
		raw := body.ID
		if strings.TrimSpace(body.Reach) != "" {
			raw = strings.TrimSpace(body.ID) + "@" + strings.TrimSpace(body.Reach)
		}
		return a.OpenChat(raw)
	})
}

func (a *App) serveSend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Text string `json:"text"`
	}
	a.serveBool(w, r, &body, func() bool { return a.Send(body.ID, body.Text) })
}

func (a *App) serveName(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	a.serveBool(w, r, &body, func() bool { return a.SetName(body.Name) })
}

func (a *App) serveTheme(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Theme string `json:"theme"`
	}
	a.serveBool(w, r, &body, func() bool { return a.SetTheme(body.Theme) })
}

func (a *App) serveUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		On bool `json:"on"`
	}
	a.serveBool(w, r, &body, func() bool { return a.SetAutoUpdate(body.On) })
}

func (a *App) serveSetup(w http.ResponseWriter, r *http.Request) {
	a.serveBool(w, r, &struct{}{}, func() bool { return a.Setup() })
}

func (a *App) serveJoin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Addr string `json:"addr"`
		Key  string `json:"key"`
	}
	a.serveBool(w, r, &body, func() bool { return a.Join(body.Addr, body.Key) })
}

func (a *App) serveRemove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	a.serveBool(w, r, &body, func() bool { return a.RemoveFriend(body.ID) })
}

func (a *App) serveAccept(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	a.serveBool(w, r, &body, func() bool { return a.AcceptSuccessor(body.ID) })
}

func (a *App) serveRecord(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Keep string `json:"keep"`
	}
	a.serveBool(w, r, &body, func() bool { return a.SetRecord(body.ID, body.Keep) })
}

func (a *App) serveRefresh(w http.ResponseWriter, r *http.Request) {
	if !a.allow(r) {
		http.NotFound(w, r)
		return
	}
	a.Refresh()
	writeJSON(w, resultJSON{OK: true, State: a.pullState()})
}

func (a *App) serveSelect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	a.serveBool(w, r, &body, func() bool { return a.Select(body.ID) })
}

func (a *App) serveBool(w http.ResponseWriter, r *http.Request, body any, fn func() bool) {
	if !a.allow(r) || !decode(w, r, body) {
		http.NotFound(w, r)
		return
	}
	ok := fn()
	writeJSON(w, resultJSON{OK: ok, State: a.pullState()})
}

func (a *App) pullState() stateJSON {
	a.mu.Lock()
	a.touchLocked()
	st := a.snapshotLocked()
	a.mu.Unlock()
	return st
}

func (a *App) allow(r *http.Request) bool {
	if !loopbackRequest(r) {
		return false
	}
	got := r.Header.Get("X-Glyph-Token")
	if got == "" {
		got = r.URL.Query().Get("t")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1
}

func decode(w http.ResponseWriter, r *http.Request, body any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(body); err != nil && err != io.EOF {
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func loopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	return loopbackHost(host)
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
