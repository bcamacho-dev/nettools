//go:build !windows

package toolbox

import "os/exec"

func configure(cmd *exec.Cmd) {}
