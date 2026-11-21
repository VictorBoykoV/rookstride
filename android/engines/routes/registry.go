// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/tun"
)

// Register only product capabilities. Unused services, cloud connectors and
// control APIs must not become part of a VPN worker's runtime surface.
func engineContext(ctx context.Context) context.Context {
	in := inbound.NewRegistry()
	socks.RegisterInbound(in)
	direct.RegisterInbound(in)
	tun.RegisterInbound(in)
	shadowsocks.RegisterInbound(in)
	hysteria2.RegisterInbound(in)
	naive.RegisterInbound(in)
	dnsRegistry := dns.NewTransportRegistry()
	transport.RegisterTCP(dnsRegistry)
	transport.RegisterUDP(dnsRegistry)
	return box.Context(ctx, in, outboundRegistry(), endpoint.NewRegistry(), dnsRegistry, service.NewRegistry(), certificate.NewRegistry())
}
func outboundRegistry() *outbound.Registry {
	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	socks.RegisterOutbound(out)
	hysteria2.RegisterOutbound(out)
	naive.RegisterOutbound(out)
	return out
}
