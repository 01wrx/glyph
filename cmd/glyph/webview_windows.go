//go:build windows

package main

import (
	"path/filepath"

	"glyph/app"

	webview "github.com/jchv/go-webview2"
)

func openWebView(url string) bool {
	w := webview.NewWithOptions(webview.WebViewOptions{
		AutoFocus: true,
		DataPath:  filepath.Join(app.DefaultHome(), "webview"),
		WindowOptions: webview.WindowOptions{
			Title:  "glyph",
			Width:  980,
			Height: 680,
			Center: true,
		},
	})
	if w == nil {
		return false
	}
	defer w.Destroy()
	w.Navigate(url)
	w.Run()
	return true
}
