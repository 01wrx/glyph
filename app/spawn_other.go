//go:build !windows

package app

import "os/exec"

func detach(cmd *exec.Cmd) {}
