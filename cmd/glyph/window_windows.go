//go:build windows

package main

import "os"

func openWindow(url string) {
	if openWebView(url) {
		return
	}
	os.Exit(1)
}
