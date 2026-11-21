// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
// The private worker accepts configuration on stdin, never in process arguments.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

const version = "rookstride-routes-1"

type workerConfig struct {
	Schema    int               `json:"schema"`
	Box       json.RawMessage   `json:"box"`
	Metrics   *metricsOptions   `json:"metrics,omitempty"`
	Websocket *websocketOptions `json:"websocket,omitempty"`
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "VPN worker failed:", err)
		os.Exit(1)
	}
}
func run() error {
	debug.SetMemoryLimit(160 * 1024 * 1024)
	var reader io.Reader = os.Stdin
	if len(os.Args) == 3 && os.Args[1] == "run" {
		f, err := os.Open(os.Args[2])
		if err != nil {
			return errors.New("configuration unavailable")
		}
		defer f.Close()
		reader = f
	}
	raw, err := io.ReadAll(io.LimitReader(reader, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 {
		return errors.New("invalid configuration size")
	}
	var cfg workerConfig
	decoder := json.NewDecoder(newReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cfg); err != nil || cfg.Schema != 1 {
		return errors.New("unsupported worker configuration")
	}
	ctx, cancel := context.WithCancel(engineContext(context.Background()))
	defer cancel()
	ctx = withAdditionalOutbounds(ctx)
	opts, err := sjson.UnmarshalExtendedContext[option.Options](ctx, cfg.Box)
	if err != nil {
		return errors.New("invalid engine options")
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}
	defer instance.Close()
	meter := newTrafficMeter(cfg.Metrics)
	instance.Router().AppendTracker(meter)
	if err = instance.Start(); err != nil {
		return fmt.Errorf("start engine: %w", err)
	}
	if cfg.Metrics != nil {
		closer, e := meter.serve()
		if e != nil {
			return e
		}
		defer closer.Close()
	}
	if cfg.Websocket != nil {
		closer, e := serveWebsocket(ctx, cfg.Websocket)
		if e != nil {
			return e
		}
		defer closer.Close()
	}
	fmt.Fprintln(os.Stderr, "VPN worker ready")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
	return nil
}

type byteReader struct{ data []byte }

func newReader(b []byte) *byteReader { return &byteReader{b} }
func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
