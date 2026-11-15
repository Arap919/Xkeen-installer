package main

import (
	"context"
	"github.com/Arap919/xkeen-installer/internal/router"
	"testing"
)

type handoffCLI struct{ config string }

func (c handoffCLI) RunCLI(context.Context, string) ([]byte, error) { return []byte(c.config), nil }

type handoffTransport struct {
	router.Transport
	entry router.Entry
}

func (t handoffTransport) Stat(context.Context, string) (router.Entry, error) { return t.entry, nil }
func TestBootstrapHandoffRequiresFinalFirmwareInitrcAndExecutableFile(t *testing.T) {
	ctx := context.Background()
	transport := handoffTransport{entry: router.Entry{Path: "/opt/etc/init.d/rc.unslung", Mode: 0755}}
	if e := verifyBootstrapHandoff(ctx, handoffCLI{"opkg initrc /opt/etc/init.d"}, transport); e == nil {
		t.Fatal("temporary Initrc accepted")
	}
	if e := verifyBootstrapHandoff(ctx, handoffCLI{"opkg initrc /opt/etc/init.d/rc.unslung"}, transport); e != nil {
		t.Fatal(e)
	}
	transport.entry.Mode = 0600
	if e := verifyBootstrapHandoff(ctx, handoffCLI{"opkg initrc /opt/etc/init.d/rc.unslung"}, transport); e == nil {
		t.Fatal("nonexecutable final init script accepted")
	}
}
