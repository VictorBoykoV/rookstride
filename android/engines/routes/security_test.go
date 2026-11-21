// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/gorilla/websocket"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testDialer struct{}

func (testDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address.String())
}
func (testDialer) ListenPacket(ctx context.Context, address M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}
func TestTrustHTTP2AuthenticatesAndValidatesCertificate(t *testing.T) {
	authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("1:1"))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != authorization {
			w.WriteHeader(407)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		buffer := make([]byte, 1024)
		for {
			n, e := r.Body.Read(buffer)
			if n > 0 {
				w.Write(buffer[:n])
				w.(http.Flusher).Flush()
			}
			if e != nil {
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	target := M.ParseSocksaddr(server.Listener.Addr().String())
	created, createErr := newTrustOutbound(context.Background(), nil, nil, "test", trustOptions{ServerOptions: option.ServerOptions{Server: target.Addr.String(), ServerPort: target.Port}, Username: "1", Password: "1", ServerName: "example.com", Certificate: certificate})
	if createErr != nil {
		t.Fatal(createErr)
	}
	client := created.(*trustOutbound)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = connection.Write([]byte("encrypted echo")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("encrypted echo"))
	if _, err = io.ReadFull(connection, data); err != nil || string(data) != "encrypted echo" {
		t.Fatal("HTTP/2 stream failed", err)
	}
	connection.Close()
	client.Close()
	client.options.ServerName = "wrong.invalid"
	client.client = nil
	if c, e := client.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443")); e == nil {
		c.Close()
		t.Fatal("Wrong server identity accepted")
	}
	client.options.ServerName = "example.com"
	client.options.Password = "bad-password"
	client.client = nil
	if c, e := client.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443")); e == nil {
		c.Close()
		t.Fatal("Wrong account accepted")
	}
}
func TestStatisticsRequireLoopbackAndAuthentication(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:0", "[::]:0", "example.com:80"} {
		m := newTrafficMeter(&metricsOptions{Listen: listen, Token: strings.Repeat("a", 64)})
		if l, e := m.serve(); e == nil {
			l.Close()
			t.Fatal("Public statistics listener accepted")
		}
	}
	m := newTrafficMeter(&metricsOptions{Listen: "127.0.0.1:0", Token: strings.Repeat("a", 64)})
	l, e := m.serve()
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	m.update("phone", 100, 200, 1)
	m.update("phone", 10, 20, -1)
	m.update("phone", 0, 0, -1)
	if m.users["phone"].Upload != 110 || m.users["phone"].Download != 220 || m.users["phone"].Sessions != 0 {
		t.Fatal("Counter direction/close accounting changed")
	}
	url := "http://" + l.Addr().String() + "/statistics"
	client := &http.Client{Timeout: time.Second}
	response, e := client.Get(url)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("Unauthenticated statistics read")
	}
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	response, e = client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || !strings.Contains(string(data), `"upload":110`) || strings.Contains(string(data), "destination") {
		t.Fatal("Incorrect or excessive statistics")
	}
	if m.generation == newTrafficMeter(nil).generation {
		t.Fatal("Daemon generations reused")
	}
}
func TestPinnedAuthorityIsRequired(t *testing.T) {
	for _, pair := range [][2]string{{"", ""}, {"server.invalid", ""}, {"server.invalid", "not a certificate"}} {
		if _, e := privateTLS(pair[0], pair[1]); e == nil {
			t.Fatal("Unverified TLS accepted")
		}
	}
}

func TestEndpointTransportRejectsEveryOtherDestination(t *testing.T) {
	target := M.ParseSocksaddr("192.0.2.10:443")
	e := &endpointOutbound{peer: target}
	for _, test := range []struct{ network, address string }{{"udp", "192.0.2.10:443"}, {"tcp", "192.0.2.11:443"}, {"tcp", "192.0.2.10:53"}, {"tcp", "example.com:443"}, {"tcp", "[2001:db8::1]:443"}} {
		if c, err := e.DialContext(context.Background(), test.network, M.ParseSocksaddr(test.address)); err == nil {
			c.Close()
			t.Fatal("Unapproved endpoint reached a transport dialer")
		}
	}
	if c, err := e.ListenPacket(context.Background(), target); err == nil {
		c.Close()
		t.Fatal("HTTP/2 transport opened a UDP socket")
	}
}

type handshakeConn struct {
	net.Conn
	success bool
}

func (c *handshakeConn) HandshakeSuccess() error { c.success = true; return nil }

type packetWithHeader struct{ N.PacketConn }

func (*packetWithHeader) FrontHeadroom() int { return 32 }
func (*packetWithHeader) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	b.ExtendHeader(32)
	b.Release()
	return nil
}
func (*packetWithHeader) Close() error { return nil }
func TestMeterPreservesHandshakeHeadroomAndCountsPayload(t *testing.T) {
	m := newTrafficMeter(&metricsOptions{})
	left, right := net.Pipe()
	defer right.Close()
	raw := &handshakeConn{Conn: left}
	c := m.RoutedConnection(context.Background(), raw, adapter.InboundContext{User: "phone"}, nil, nil)
	if e := N.ReportHandshakeSuccess(c); e != nil || !raw.success {
		t.Fatal("Meter hid the transport handshake")
	}
	c.Close()
	original := &packetWithHeader{}
	packet := m.RoutedPacketConnection(context.Background(), original, adapter.InboundContext{User: "phone"}, nil, nil)
	headroom := N.CalculateFrontHeadroom(packet)
	if headroom != 32 {
		t.Fatal("Meter hid packet header space", headroom)
	}
	b := buf.NewSize(64)
	b.Resize(headroom, 0)
	b.WriteString("data")
	if e := packet.WritePacket(b, M.ParseSocksaddr("192.0.2.1:53")); e != nil {
		t.Fatal(e)
	}
	packet.Close()
	packet.Close()
	if m.users["phone"].Download != 4 || m.users["phone"].Sessions != 0 {
		t.Fatal("Incorrect payload/close accounting")
	}
	if newTrafficMeter(nil).RoutedPacketConnection(context.Background(), original, adapter.InboundContext{}, nil, nil) != original {
		t.Fatal("Unmetered packet path was changed")
	}
}

func TestMeterPropagatesEOFWithoutAnUnderlyingHalfClose(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	meter := newTrafficMeter(&metricsOptions{})
	wrapped := &meterConn{Conn: left, m: meter, user: "phone"}
	if e := wrapped.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	right.SetReadDeadline(time.Now().Add(time.Second))
	one := make([]byte, 1)
	if _, e := right.Read(one); e != io.EOF {
		t.Fatal("Transport EOF was hidden", e)
	}
}

func TestWebsocketRelaySendsPayloadThenNormalEOF(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := fixture.TLS.Certificates[0]
	fixture.Close()
	folder := t.TempDir()
	cert := filepath.Join(folder, "cert.pem")
	key := filepath.Join(folder, "key.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600)
	der, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, e := backend.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 4)
		if _, e = io.ReadFull(c, b); e == nil {
			c.Write([]byte("complete-body"))
		}
	}()
	path := "/" + strings.Repeat("a", 48)
	listener, err := serveWebsocket(context.Background(), &websocketOptions{Listen: "127.0.0.1:0", Certificate: cert, Key: key, Targets: map[string]string{path: backend.Addr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tlsConfig, err := privateTLS("example.com", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})))
	if err != nil {
		t.Fatal(err)
	}
	dialer := websocket.Dialer{TLSClientConfig: tlsConfig, HandshakeTimeout: time.Second}
	c, _, err := dialer.Dial("wss://"+listener.Addr().String()+path+"/tcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if e := c.WriteMessage(websocket.BinaryMessage, []byte("ping")); e != nil {
		t.Fatal(e)
	}
	_, body, err := c.ReadMessage()
	if err != nil || string(body) != "complete-body" {
		t.Fatal("Relay lost its final payload", err)
	}
	if _, _, err = c.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatal("Relay reset instead of normal EOF", err)
	}
}
