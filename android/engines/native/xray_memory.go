// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Added to the pinned MIT libXray package by build-engines.py.
package libXray

import (
 "errors"
 "runtime/debug"
 "strings"
 "syscall"
 "github.com/xtls/xray-core/core"
 xinternet "github.com/xtls/xray-core/transport/internet"
)
var memoryCore *core.Instance
// StartMemory avoids writing connection credentials to a plaintext config file.
func StartMemory(config string) string {
 debug.SetMemoryLimit(192*1024*1024)
 parsed,err:=core.LoadConfig("json",strings.NewReader(config));if err!=nil{return err.Error()}
 memoryCore,err=core.New(parsed);if err!=nil{return err.Error()}
 if err=memoryCore.Start();err!=nil{memoryCore.Close();memoryCore=nil;return err.Error()}
 return ""
}
func StopMemory() string {if memoryCore==nil{return ""};err:=memoryCore.Close();memoryCore=nil;if err!=nil{return err.Error()};return ""}
// A failed Android protect() must abort a socket rather than recurse into TUN.
func RegisterProtection(controller DialerController) string {
 control:=func(network,address string,conn syscall.RawConn) error{
  ok:=false;err:=conn.Control(func(fd uintptr){ok=controller.ProtectFd(int(fd))});if err!=nil{return err};if !ok{return errors.New("VPN socket protection failed")};return nil
 }
 if err:=xinternet.RegisterDialerController(control);err!=nil{return err.Error()}
 if err:=xinternet.RegisterListenerController(control);err!=nil{return err.Error()}
 return ""
}
