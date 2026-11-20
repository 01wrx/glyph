package app

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"glyph/direct"
)

var publicClient = &http.Client{Timeout: 4 * time.Second}

func (a *App) applyNetwork() {
	name, ip := fetchPublic()
	if name == "" {
		name = "network unavailable"
	}
	a.mu.Lock()
	a.network = name
	a.publicIP = ip
	a.mu.Unlock()
}

func fetchPublic() (name, ip string) {
	trace, err := httpLimited("https://1.1.1.1/cdn-cgi/trace")
	if err == nil {
		ip = traceValue(trace, "ip")
		if traceValue(trace, "warp") == "on" {
			return "Cloudflare", ip
		}
	}
	body, err := httpLimited("https://ipwho.is/")
	if err == nil {
		var info struct {
			Success    bool   `json:"success"`
			IP         string `json:"ip"`
			Connection struct {
				ISP string `json:"isp"`
				Org string `json:"org"`
			} `json:"connection"`
		}
		if json.Unmarshal(body, &info) == nil && info.Success {
			if ip == "" {
				ip = info.IP
			}
			if info.Connection.ISP != "" {
				return cleanNetName(info.Connection.ISP), ip
			}
			if info.Connection.Org != "" {
				return cleanNetName(info.Connection.Org), ip
			}
		}
	}
	return "", ip
}

func httpLimited(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "glyph")
	resp, err := publicClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, io.ErrUnexpectedEOF
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

func traceValue(body []byte, key string) string {
	prefix := key + "="
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func cleanNetName(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "AS") {
		i := strings.IndexAny(s, " \t")
		if i > 2 && digits(s[2:i]) {
			s = strings.TrimSpace(s[i+1:])
		}
	}
	for _, suffix := range []string{", Inc.", " Inc.", ", LLC", " LLC", ", Ltd.", " Ltd."} {
		s = strings.TrimSuffix(s, suffix)
	}
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func publicReach(ip string, n *direct.Node) string {
	if n == nil {
		return ""
	}
	_, port, err := net.SplitHostPort(n.Addr())
	if err != nil || port == "" {
		return ""
	}
	if ip == "" {
		return "port " + port
	}
	return net.JoinHostPort(ip, port)
}

func (a *App) lanTCP() string {
	if a == nil || a.node == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(a.node.Addr())
	if err != nil || port == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return a.node.Addr()
	}
	priv := privateIPv4()
	if priv == "" {
		return ""
	}
	return net.JoinHostPort(priv, port)
}

func (a *App) noteLAN(peer, addr string) {
	if a == nil || a.node == nil {
		return
	}
	_ = a.node.SetReach(peer, addr)
}
