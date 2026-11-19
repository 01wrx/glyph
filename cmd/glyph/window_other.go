//go:build !windows

package main

import (
	"os/exec"
	"runtime"
)

func openWindow(url string) {
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
	sigWait()
}

func sigWait() {
	// The page is open in a browser. Stay up until the process is interrupted.
	select {}
}
