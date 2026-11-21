// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Independent HTTP/2 client for TrustTunnel protocol v1.0. The official endpoint
// and specification retain Apache-2.0. All endpoint sockets use the protected dialer.
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"crypto/tls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

type trustOptions struct {
	option.DialerOptions
	option.ServerOptions
	Username    string `json:"username"`
	Password    string `json:"password"`
	ServerName  string `json:"server_name"`
	Certificate string `json:"certificate"`
}

func registerTrust(registry *outbound.Registry) {
	outbound.Register[trustOptions](registry, "trusttunnel-h2", newTrustOutbound)
}

type trustOutbound struct {
	outbound.Adapter
	options   trustOptions
	dialer    N.Dialer
	mu        sync.Mutex
	client    *http2.ClientConn
	transport net.Conn
}

func newTrustOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, o trustOptions) (adapter.Outbound, error) {
	if o.Username == "" || o.Password == "" {
		return nil, errors.New("missing TrustTunnel account")
	}
	if _, e := privateTLS(o.ServerName, o.Certificate); e != nil {
		return nil, e
	}
	d, e := dialer.New(ctx, o.DialerOptions, false)
	if e != nil {
		return nil, e
	}
	if !o.ServerOptions.Build().IsIP() {
		return nil, errors.New("resolve VPN endpoint before starting")
	}
	return &trustOutbound{Adapter: outbound.NewAdapterWithDialerOptions("trusttunnel-h2", tag, []string{"tcp", "udp"}, o.DialerOptions), options: o, dialer: d}, nil
}
func (t *trustOutbound) session(ctx context.Context) (*http2.ClientConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil && t.client.CanTakeNewRequest() {
		return t.client, nil
	}
	if t.transport != nil {
		t.transport.Close()
		t.transport = nil
	}
	c, e := t.dialer.DialContext(ctx, "tcp", t.options.ServerOptions.Build())
	if e != nil {
		return nil, e
	}
	cfg, _ := privateTLS(t.options.ServerName, t.options.Certificate)
	cfg.NextProtos = []string{"h2"}
	tlsConn := tls.Client(c, cfg)
	if e = tlsConn.HandshakeContext(ctx); e != nil {
		c.Close()
		return nil, e
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return nil, errors.New("server did not negotiate HTTP/2")
	}
	client, e := (&http2.Transport{ReadIdleTimeout: 30 * time.Second, PingTimeout: 15 * time.Second}).NewClientConn(tlsConn)
	if e != nil {
		tlsConn.Close()
		return nil, e
	}
	t.transport = tlsConn
	t.client = client
	return client, nil
}
func (t *trustOutbound) stream(ctx context.Context, target, kind string) (*httpTunnel, error) {
	client, e := t.session(ctx)
	if e != nil {
		return nil, e
	}
	reader, writer := io.Pipe()
	requestCtx, cancel := context.WithCancel(ctx)
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: target}, Host: target, Header: make(http.Header), Body: reader, ContentLength: -1}
	request = request.WithContext(requestCtx)
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(t.options.Username+":"+t.options.Password)))
	request.Header.Set("User-Agent", "Rookstride "+kind)
	response, e := client.RoundTrip(request)
	if e != nil {
		cancel()
		reader.Close()
		writer.Close()
		return nil, e
	}
	if response.StatusCode != 200 {
		cancel()
		response.Body.Close()
		reader.Close()
		writer.Close()
		return nil, errors.New("TrustTunnel authentication or connection rejected")
	}
	return &httpTunnel{reader: response.Body, writer: writer, cancel: cancel, remote: M.ParseSocksaddr(target).TCPAddr()}, nil
}
func (t *trustOutbound) DialContext(ctx context.Context, network string, d M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("use packet connection for UDP")
	}
	return t.stream(ctx, d.String(), "_tcp")
}
func (t *trustOutbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	s, e := t.stream(ctx, "_udp2", "_udp2")
	if e != nil {
		return nil, e
	}
	return &trustPacket{stream: s, port: uint16(20000 + udpSequence.Add(1)%40000)}, nil
}
func (t *trustOutbound) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.transport != nil {
		return t.transport.Close()
	}
	return nil
}

type httpTunnel struct {
	reader     io.ReadCloser
	writer     *io.PipeWriter
	cancel     context.CancelFunc
	remote     net.Addr
	once       sync.Once
	deadlineMu sync.Mutex
	timer      *time.Timer
}

func (s *httpTunnel) Read(b []byte) (int, error)  { return s.reader.Read(b) }
func (s *httpTunnel) Write(b []byte) (int, error) { return s.writer.Write(b) }
func (s *httpTunnel) Close() error {
	s.once.Do(func() {
		s.cancel()
		s.writer.Close()
		s.reader.Close()
		s.deadlineMu.Lock()
		if s.timer != nil {
			s.timer.Stop()
		}
		s.deadlineMu.Unlock()
	})
	return nil
}
func (s *httpTunnel) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 254, 254, 1), Port: 0}
}
func (s *httpTunnel) RemoteAddr() net.Addr { return s.remote }
func (s *httpTunnel) SetDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	if !t.IsZero() {
		s.timer = time.AfterFunc(time.Until(t), func() { s.cancel(); s.writer.CloseWithError(os.ErrDeadlineExceeded); s.reader.Close() })
	}
	return nil
}
func (s *httpTunnel) SetReadDeadline(t time.Time) error  { return s.SetDeadline(t) }
func (s *httpTunnel) SetWriteDeadline(t time.Time) error { return s.SetDeadline(t) }

var udpSequence atomic.Uint32

type trustPacket struct {
	stream          *httpTunnel
	port            uint16
	readMu, writeMu sync.Mutex
}

func (p *trustPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	target := M.SocksaddrFromNet(a)
	if !target.IsIP() || len(b) > 65507 {
		return 0, errors.New("invalid TrustTunnel datagram")
	}
	frame := make([]byte, 41+len(b))
	binary.BigEndian.PutUint32(frame, uint32(len(frame)-4))
	copy(frame[16:20], net.IPv4(10, 254, 254, 1).To4())
	binary.BigEndian.PutUint16(frame[20:22], p.port)
	ip := target.Addr.AsSlice()
	if len(ip) == 4 {
		copy(frame[34:38], ip)
	} else {
		copy(frame[22:38], ip)
	}
	binary.BigEndian.PutUint16(frame[38:40], target.Port)
	frame[40] = 0
	copy(frame[41:], b)
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_, e := p.stream.Write(frame)
	if e != nil {
		return 0, e
	}
	return len(b), nil
}
func (p *trustPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	header := make([]byte, 4)
	if _, e := io.ReadFull(p.stream, header); e != nil {
		return 0, nil, e
	}
	size := binary.BigEndian.Uint32(header)
	if size < 36 || size > 65571 {
		return 0, nil, errors.New("invalid TrustTunnel packet size")
	}
	frame := make([]byte, size)
	if _, e := io.ReadFull(p.stream, frame); e != nil {
		return 0, nil, e
	}
	source := net.IP(frame[:16])
	if equalZero(frame[:12]) {
		source = net.IP(frame[12:16])
	}
	address := &net.UDPAddr{IP: source, Port: int(binary.BigEndian.Uint16(frame[16:18]))}
	payload := frame[36:]
	n := copy(b, payload)
	if n < len(payload) {
		return n, address, io.ErrShortBuffer
	}
	return n, address, nil
}
func equalZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func (p *trustPacket) Close() error { return p.stream.Close() }
func (p *trustPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(10, 254, 254, 1), Port: int(p.port)}
}
func (p *trustPacket) SetDeadline(t time.Time) error      { return p.stream.SetDeadline(t) }
func (p *trustPacket) SetReadDeadline(t time.Time) error  { return p.stream.SetReadDeadline(t) }
func (p *trustPacket) SetWriteDeadline(t time.Time) error { return p.stream.SetWriteDeadline(t) }
