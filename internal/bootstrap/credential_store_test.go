package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialPublicationRejectsForeignAndTampered(t *testing.T) {
	payload := []byte("XKEEN-BOOTSTRAP-V1\n" + strings.Repeat("a", 32) + "\n12345678-abcd-1234-abcd-123456789abc\narm64\n" + strings.Repeat("b", 64) + "\n$6$rounds=100000$abcdefghijklmnop$" + strings.Repeat(".", 86) + "\n")
	for _, scenario := range []string{"valid", "foreign", "symlink", "readback"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			d := localDisk{root: root}
			if scenario == "foreign" {
				os.WriteFile(filepath.Join(root, credentialName), []byte("foreign"), 0600)
			}
			if scenario == "symlink" {
				os.Symlink("foreign", filepath.Join(root, credentialName))
			}
			if scenario == "readback" {
				d.corrupt = true
			}
			err := publishCredentialDisk(d, payload)
			if scenario == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				got, _ := os.ReadFile(filepath.Join(root, credentialName))
				if !bytes.Equal(got, payload) {
					t.Fatal("credential not published")
				}
				if err = checkCredentialDisk(d, payload); err != nil {
					t.Fatal(err)
				}
				os.WriteFile(filepath.Join(root, credentialName), []byte("tampered"), 0600)
				if checkCredentialDisk(d, payload) == nil {
					t.Fatal("tampered credential accepted")
				}
			} else if err == nil {
				t.Fatal("unsafe publication accepted")
			}
		})
	}
}
func TestBootstrapCredentialFailurePreventsFirmwareTrigger(t *testing.T) {
	c := &fixtureCLI{config: "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/", media: mediaFixture}
	st := &fixtureStore{credentialFailure: true}
	s := NewSession(c, st)
	s.download = func(context.Context, catalog.Artifact) ([]byte, error) { return []byte("fixture"), nil }
	p, err := s.Prepare(context.Background(), "", "Fixture-password-2026!", "Fixture-password-2026!")
	if err != nil {
		t.Fatal(err)
	}
	if s.Start(context.Background(), p.ID, true, nil) == nil || c.writes != 0 {
		t.Fatal("triggered before credential verification")
	}
}

func TestCredentialPlanNeverExposesHashAndInvalidPreparationRevokes(t *testing.T) {
	c := &fixtureCLI{config: "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/", media: mediaFixture}
	s := NewSession(c, &fixtureStore{})
	password := "Fixture-password-2026!"
	p, err := s.Prepare(context.Background(), "", password, password)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), password) || strings.Contains(string(data), "$6$") {
		t.Fatal("secret crossed public plan boundary")
	}
	if !validCredentialPayload(s.credential) {
		t.Fatal("private credential missing")
	}
	if _, err = s.Prepare(context.Background(), "", "short", "short"); err == nil {
		t.Fatal("invalid password accepted")
	}
	if len(s.credential) != 0 || s.plan.ID != "" {
		t.Fatal("invalid preparation retained prior approval")
	}
	if s.Start(context.Background(), p.ID, true, nil) == nil || c.writes != 0 {
		t.Fatal("revoked plan triggered firmware")
	}
}

func TestCorruptPrivateCredentialConsumesPlan(t *testing.T) {
	c := &fixtureCLI{config: "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/", media: mediaFixture}
	s := NewSession(c, &fixtureStore{})
	p, err := s.Prepare(context.Background(), "", "Fixture-password-2026!", "Fixture-password-2026!")
	if err != nil {
		t.Fatal(err)
	}
	s.credential = []byte("invalid")
	if s.Start(context.Background(), p.ID, true, nil) == nil || s.plan.ID != "" || c.writes != 0 {
		t.Fatal("invalid private state did not consume approval")
	}
}
