// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type metricsOptions struct {
	Listen string            `json:"listen"`
	Token  string            `json:"token"`
	Users  map[string]string `json:"users"`
}
type trafficAccount struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
	Sessions uint64 `json:"sessions"`
	Updated  int64  `json:"updated"`
}
type trafficMeter struct {
	mu         sync.Mutex
	users      map[string]*trafficAccount
	options    *metricsOptions
	generation string
	started    int64
}

func newTrafficMeter(o *metricsOptions) *trafficMeter {
	b := make([]byte, 16)
	rand.Read(b)
	return &trafficMeter{users: make(map[string]*trafficAccount), options: o, generation: hex.EncodeToString(b), started: time.Now().Unix()}
}
func (m *trafficMeter) account(metadata adapter.InboundContext) string {
	if m.options == nil {
		return ""
	}
	if name, ok := m.options.Users[metadata.Inbound]; ok {
		return name
	}
	return metadata.User
}
func (m *trafficMeter) update(user string, upload, download uint64, delta int) {
	if user == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.users[user]
	if v == nil {
		v = &trafficAccount{}
		m.users[user] = v
	}
	v.Upload += upload
	v.Download += download
	if delta > 0 {
		v.Sessions++
	} else if delta < 0 && v.Sessions > 0 {
		v.Sessions--
	}
	v.Updated = time.Now().Unix()
}
func (m *trafficMeter) RoutedConnection(_ context.Context, c net.Conn, md adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	user := m.account(md)
	if user == "" {
		return c
	}
	m.update(user, 0, 0, 1)
	return &meterConn{Conn: c, m: m, user: user}
}
func (m *trafficMeter) RoutedPacketConnection(_ context.Context, c N.PacketConn, md adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	user := m.account(md)
	if user == "" {
		return c
	}
	m.update(user, 0, 0, 1)
	return &meterPacket{PacketConn: c, m: m, user: user}
}
func (m *trafficMeter) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

type meterConn struct {
	net.Conn
	m    *trafficMeter
	user string
	once sync.Once
}

func (c *meterConn) Upstream() any         { return c.Conn }
func (*meterConn) ReaderReplaceable() bool { return false }
func (*meterConn) WriterReplaceable() bool { return false }
func (c *meterConn) CloseRead() error      { return N.CloseRead(c.Conn) }
func (c *meterConn) CloseWrite() error {
	writer, _ := N.UnwrapCountWriter(c.Conn, nil)
	if half, ok := N.UnwrapWriter(writer).(N.WriteCloser); ok {
		return half.CloseWrite()
	}
	// Advertising a no-op CloseWrite hides EOF on QUIC/WebSocket transports.
	// Match the router's normal full-close fallback when half-close is absent.
	return c.Conn.Close()
}

func (c *meterConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.m.update(c.user, uint64(n), 0, 0)
	return n, e
}
func (c *meterConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.m.update(c.user, 0, uint64(n), 0)
	return n, e
}
func (c *meterConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.m.update(c.user, 0, 0, -1) })
	return e
}

type meterPacket struct {
	N.PacketConn
	m    *trafficMeter
	user string
	once sync.Once
}

// Introspection must reach handshake and buffer-headroom contracts. I/O itself
// stays wrapped so optimized copies cannot silently skip the counters.
func (c *meterPacket) Upstream() any         { return c.PacketConn }
func (*meterPacket) ReaderReplaceable() bool { return false }
func (*meterPacket) WriterReplaceable() bool { return false }

func (c *meterPacket) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	a, e := c.PacketConn.ReadPacket(b)
	if e == nil {
		c.m.update(c.user, uint64(b.Len()), 0, 0)
	}
	return a, e
}
func (c *meterPacket) WritePacket(b *buf.Buffer, a M.Socksaddr) error {
	n := b.Len()
	e := c.PacketConn.WritePacket(b, a)
	if e == nil {
		c.m.update(c.user, 0, uint64(n), 0)
	}
	return e
}
func (c *meterPacket) Close() error {
	e := c.PacketConn.Close()
	c.once.Do(func() { c.m.update(c.user, 0, 0, -1) })
	return e
}
func (m *trafficMeter) serve() (net.Listener, error) {
	host, _, e := net.SplitHostPort(m.options.Listen)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || len(m.options.Token) < 32 {
		return nil, errors.New("statistics must use authenticated loopback")
	}
	listener, e := net.Listen("tcp", m.options.Listen)
	if e != nil {
		return nil, e
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/statistics", func(w http.ResponseWriter, r *http.Request) {
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if r.Method != "GET" || subtle.ConstantTimeCompare([]byte(supplied), []byte(m.options.Token)) != 1 {
			http.Error(w, "Unauthorized", 401)
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"generation": m.generation, "started": m.started, "users": m.users, "scope": "current daemon generation"})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second}
	go server.Serve(listener)
	return listener, nil
}
