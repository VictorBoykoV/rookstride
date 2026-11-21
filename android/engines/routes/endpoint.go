// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net"
)

type endpointOptions struct {
	option.DialerOptions
	option.ServerOptions
}
type endpointOutbound struct {
	outbound.Adapter
	peer   M.Socksaddr
	dialer N.Dialer
}

func registerEndpoint(r *outbound.Registry) {
	outbound.Register[endpointOptions](r, "endpoint-only", newEndpointOutbound)
}
func newEndpointOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, o endpointOptions) (adapter.Outbound, error) {
	peer := o.ServerOptions.Build()
	if !peer.IsIP() || peer.Port == 0 {
		return nil, errors.New("literal transport endpoint required")
	}
	d, e := dialer.New(ctx, o.DialerOptions, false)
	if e != nil {
		return nil, e
	}
	return &endpointOutbound{Adapter: outbound.NewAdapterWithDialerOptions("endpoint-only", tag, []string{"tcp"}, o.DialerOptions), peer: peer, dialer: d}, nil
}
func (e *endpointOutbound) DialContext(ctx context.Context, network string, d M.Socksaddr) (net.Conn, error) {
	if network != "tcp" || d != e.peer {
		return nil, errors.New("transport attempted an unapproved endpoint")
	}
	return e.dialer.DialContext(ctx, "tcp", d)
}
func (*endpointOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("UDP transport is disabled for HTTP/2")
}
