package main

import (
	"errors"
	"github.com/Arap919/xkeen-installer/internal/bootstrap"
	"strings"
	"testing"
)

func TestBootstrapRejectsInvalidConnectionAndUnreviewedStart(t *testing.T) {
	a := newApp()
	if _, err := a.DiscoverBootstrap(ConnectionRequest{Host: "bad\nvalue", Port: 22, User: "admin", Password: "private"}); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("unsafe input error")
	}
	if err := a.StartBootstrap("invented", true); err == nil {
		t.Fatal("unprepared bootstrap started")
	}
}

func TestCIFSReadAndParseFailuresAreDistinct(t *testing.T) {
	for stage, want := range map[string]string{"show cifs": "[BOOTSTRAP_CIFS]", "parse cifs": "[BOOTSTRAP_CIFS_PARSE]"} {
		got := bootstrapDiscoveryFailure(&bootstrap.DiscoveryError{Stage: stage}).Error()
		if !strings.Contains(got, want) {
			t.Fatal("CIFS command and parser failures conflated", got)
		}
	}
}

func TestCIFSParseDiagnosticIsSafeAcrossBridge(t *testing.T) {
	err := errors.Join(&bootstrap.DiscoveryError{Stage: "parse cifs"}, &bootstrap.CIFSParseError{Reason: "TEXT", Line: 7, Field: "none"})
	got := bootstrapDiscoveryFailure(err).Error()
	if !strings.Contains(got, "CIFS/TEXT/7/none") {
		t.Fatal("diagnostic lost", got)
	}
	err = errors.Join(&bootstrap.DiscoveryError{Stage: "parse cifs"}, &bootstrap.CIFSParseError{Reason: "private-password", Line: 7, Field: "private-value"})
	got = bootstrapDiscoveryFailure(err).Error()
	if strings.Contains(got, "private") {
		t.Fatal("unsafe diagnostic crossed bridge", got)
	}
}

func TestBootstrapStartFailureIdentifiesStageWithoutPrivateCause(t *testing.T) {
	for stage, want := range map[string]string{"transfer": "[BOOTSTRAP/TRANSFER]", "download": "[BOOTSTRAP/DOWNLOAD]", "post-transfer-inspect": "[BOOTSTRAP/POST_TRANSFER_INSPECT]", "store-check": "[BOOTSTRAP/STORE_CHECK]"} {
		got := bootstrapStartFailure(&bootstrap.StartError{Stage: stage}).Error()
		if !strings.Contains(got, want) {
			t.Fatalf("stage %s lost: %s", stage, got)
		}
	}
	got := bootstrapStartFailure(errors.New("private-password")).Error()
	if strings.Contains(got, "private") {
		t.Fatal("private cause leaked")
	}
}
