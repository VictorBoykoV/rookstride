//go:build linux && !android

// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	tun "github.com/sagernet/sing-tun"
	"testing"
)

func TestLinuxBridgePacketStackIsIncluded(t *testing.T) {
	if !tun.WithGVisor {
		t.Fatal("Linux bridges require -tags with_gvisor")
	}
}
