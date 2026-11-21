//go:build linux && !android

// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"encoding/json"
	tun "github.com/sagernet/sing-tun"
	"os"
	"runtime"
)

// The phone uses its own packet adapter. Linux bridges must carry a real TUN
// stack; report this before installing a service that could only fail/restart.
func init() {
	if len(os.Args) == 2 && os.Args[1] == "features" {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "os": runtime.GOOS, "architecture": runtime.GOARCH, "tun_gvisor": tun.WithGVisor})
		os.Exit(0)
	}
}
