// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Outline SDK retains its Apache-2.0 license. No cipher is implemented here.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"golang.getoutline.org/sdk/transport"
	ss "golang.getoutline.org/sdk/transport/shadowsocks"
	ws "golang.getoutline.org/sdk/x/websocket"
)

func withAdditionalOutbounds(ctx context.Context) context.Context {
	registry := outboundRegistry()
	outbound.Register[outlineOptions](registry, "outline-wss", newOutlineOutbound)
	registerTrust(registry)
	registerEndpoint(registry)
	ctx = service.ContextWith[adapter.OutboundRegistry](ctx, registry)
	return service.ContextWith[option.OutboundOptionsRegistry](ctx, registry)
}

type outlineOptions struct {
	option.DialerOptions
	option.ServerOptions
	Password    string `json:"password"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Certificate string `json:"certificate"`
	ServerName  string `json:"server_name"`
}
type streamEndpoint func(context.Context) (transport.StreamConn, error)

func (e streamEndpoint) ConnectStream(c context.Context) (transport.StreamConn, error) { return e(c) }

type halfConn struct{ net.Conn }

func (c halfConn) CloseRead() error {
	if v, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return v.CloseRead()
	}
	return nil
}
func (c halfConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return c.Close()
}

type outlineOutbound struct {
	outbound.Adapter
	dial   *ss.StreamDialer
	packet func(context.Context) (net.Conn, error)
	key    *ss.EncryptionKey
}

func privateTLS(name, certificate string) (*tls.Config, error) {
	if name == "" || certificate == "" {
		return nil, errors.New("verified server identity required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(certificate)) {
		return nil, errors.New("invalid pinned certificate authority")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: name}, nil
}
func newOutlineOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, o outlineOptions) (adapter.Outbound, error) {
	if o.Method != "chacha20-ietf-poly1305" || len(o.Password) < 24 || !strings.HasPrefix(o.Path, "/") || strings.ContainsAny(o.Path, "?#\r\n") {
		return nil, errors.New("invalid Shadowsocks WebSocket profile")
	}
	tlsConfig, err := privateTLS(o.ServerName, o.Certificate)
	if err != nil {
		return nil, err
	}
	d, err := dialer.New(ctx, o.DialerOptions, false)
	if err != nil {
		return nil, err
	}
	address := o.ServerOptions.Build()
	if !address.IsIP() {
		return nil, errors.New("resolve VPN endpoint before starting")
	}
	endpoint := streamEndpoint(func(ctx context.Context) (transport.StreamConn, error) {
		c, e := d.DialContext(ctx, "tcp", address)
		if e != nil {
			return nil, e
		}
		return halfConn{c}, nil
	})
	base := url.URL{Scheme: "wss", Host: net.JoinHostPort(o.ServerName, fmtPort(o.ServerPort)), Path: o.Path + "/tcp"}
	se, err := ws.NewStreamEndpoint(base.String(), endpoint, ws.WithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	base.Path = o.Path + "/udp"
	pe, err := ws.NewPacketEndpoint(base.String(), endpoint, ws.WithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	key, err := ss.NewEncryptionKey(o.Method, o.Password)
	if err != nil {
		return nil, err
	}
	sd, err := ss.NewStreamDialer(streamEndpoint(se), key)
	if err != nil {
		return nil, err
	}
	return &outlineOutbound{Adapter: outbound.NewAdapterWithDialerOptions("outline-wss", tag, []string{"tcp", "udp"}, o.DialerOptions), dial: sd, packet: pe, key: key}, nil
}
func (o *outlineOutbound) DialContext(ctx context.Context, network string, d M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("use packet connection for UDP")
	}
	return o.dial.DialStream(ctx, d.String())
}
func (o *outlineOutbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	c, e := o.packet(ctx)
	if e != nil {
		return nil, e
	}
	return ss.NewPacketConn(c, o.key), nil
}

// One shared TLS listener routes each unguessable path to that user's private
// Shadowsocks listener. The cryptographic protocol authenticates the payload.
type websocketOptions struct {
	Listen      string            `json:"listen"`
	Certificate string            `json:"certificate_path"`
	Key         string            `json:"key_path"`
	Targets     map[string]string `json:"targets"`
}

func serveWebsocket(ctx context.Context, o *websocketOptions) (net.Listener, error) {
	cert, e := tls.LoadX509KeyPair(o.Certificate, o.Key)
	if e != nil {
		return nil, errors.New("WebSocket certificate unavailable")
	}
	for path, target := range o.Targets {
		host, _, err := net.SplitHostPort(target)
		if !strings.HasPrefix(path, "/") || len(path) < 24 || strings.ContainsAny(path, "?#\r\n") || err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return nil, errors.New("invalid private WebSocket target")
		}
	}
	listener, e := tls.Listen("tcp", o.Listen, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if e != nil {
		return nil, e
	}
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{ReadBufferSize: 16384, WriteBufferSize: 16384, CheckOrigin: func(*http.Request) bool { return true }}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mode := ""
		path := r.URL.Path
		for _, suffix := range []string{"/tcp", "/udp"} {
			if strings.HasSuffix(path, suffix) {
				mode = suffix[1:]
				path = strings.TrimSuffix(path, suffix)
				break
			}
		}
		target, ok := o.Targets[path]
		if !ok || mode == "" || r.Method != "GET" {
			http.NotFound(w, r)
			return
		}
		// Connecting the private upstream before Upgrade avoids an orphaned socket.
		conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.Context(), mode, target)
		if err != nil {
			http.Error(w, "Unavailable", 503)
			return
		}
		defer conn.Close()
		sock, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer sock.Close()
		sock.SetReadLimit(65536)
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer sock.Close()
			buffer := make([]byte, 65536)
			for {
				n, e := conn.Read(buffer)
				if n > 0 {
					if sock.WriteMessage(websocket.BinaryMessage, buffer[:n]) != nil {
						return
					}
				}
				if e != nil {
					// A raw TLS close becomes WebSocket 1006/reset at the client,
					// even after a complete DNS/HTTP payload. Signal normal EOF.
					sock.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
					return
				}
			}
		}()
		for {
			kind, b, e := sock.ReadMessage()
			if e != nil || kind != websocket.BinaryMessage {
				break
			}
			if mode == "udp" {
				if len(b) > 16384 {
					break
				}
				_, e = conn.Write(b)
			} else {
				_, e = io.Copy(conn, newReader(b))
			}
			if e != nil {
				break
			}
		}
		conn.Close()
		sock.Close()
		<-done
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	go server.Serve(listener)
	return listener, nil
}

var _ N.Dialer = (*outlineOutbound)(nil)

func fmtPort(v uint16) string { return strconv.Itoa(int(v)) }
