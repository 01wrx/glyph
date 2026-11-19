module glyph

go 1.26.11

require (
	filippo.io/edwards25519 v1.1.1
	glyph-mailbox v0.0.0
	golang.org/x/crypto v0.59.0
)

require (
	github.com/jchv/go-webview2 v0.0.0-20260205173254-56598839c808 // indirect
	github.com/jchv/go-winloader v0.0.0-20250406163304-c1995be93bd1 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace glyph-mailbox => ../glyph-mailbox
