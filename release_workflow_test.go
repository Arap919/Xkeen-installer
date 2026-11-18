package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type provenanceWorkflow struct {
	Permissions map[string]string
	Jobs        map[string]struct {
		If          string
		RunsOn      string `yaml:"runs-on"`
		Permissions map[string]string
		Steps       []struct {
			ID, Uses, Run, Shell, If string
			With                     map[string]any
			ContinueOnError          bool `yaml:"continue-on-error"`
		}
	}
}

func readProvenanceWorkflow(t *testing.T) provenanceWorkflow {
	t.Helper()
	data, err := os.ReadFile(".github/workflows/build.yml")
	if err != nil {
		t.Fatal(err)
	}
	var w provenanceWorkflow
	if err = yaml.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	return w
}
func provenanceRun(t *testing.T, id string) string {
	t.Helper()
	for _, step := range readProvenanceWorkflow(t).Jobs["release"].Steps {
		if step.ID == id {
			return step.Run
		}
	}
	t.Fatalf("missing release step %s", id)
	return ""
}
func TestReleaseProvenanceTrustBoundary(t *testing.T) {
	w := readProvenanceWorkflow(t)
	if len(w.Permissions) != 1 || w.Permissions["contents"] != "read" {
		t.Fatal("workflow must default to read only")
	}
	release := w.Jobs["release"]
	if release.If != "(github.event_name == 'push' || github.event_name == 'workflow_dispatch') && github.ref == 'refs/heads/main'" {
		t.Fatal("provenance must be main-only and exclude PRs")
	}
	if release.RunsOn != "ubuntu-24.04" {
		t.Fatal("release scripts require the isolated Linux runner")
	}
	for name, job := range w.Jobs {
		if name == "release" {
			continue
		}
		if job.Permissions["id-token"] == "write" || job.Permissions["attestations"] == "write" {
			t.Fatalf("signing permission outside release job: %s", name)
		}
	}
	if len(release.Permissions) != 3 || release.Permissions["contents"] != "write" || release.Permissions["id-token"] != "write" || release.Permissions["attestations"] != "write" {
		t.Fatal("missing or excessive release signing permissions")
	}
	order := map[string]int{}
	count := 0
	for name, job := range w.Jobs {
		for index, step := range job.Steps {
			if name == "release" {
				order[step.ID] = index
				switch step.ID {
				case "prepare-release", "attest-release", "verify-release", "publish-release":
					if step.ContinueOnError || step.If != "" {
						t.Fatal("provenance steps must not be skipped or ignore failure")
					}
				}
			}
			if strings.HasPrefix(step.Uses, "actions/attest@") {
				count++
				if name != "release" || !regexp.MustCompile(`^actions/attest@[a-f0-9]{40}$`).MatchString(step.Uses) {
					t.Fatal("attestation must use a pinned action in release only")
				}
				if step.ID != "attest-release" || step.With["subject-path"] != "release/*" || step.ContinueOnError {
					t.Fatal("attestation must cover all final files and fail closed")
				}
			}
		}
	}
	if count != 1 {
		t.Fatal("expected exactly one release attestation step")
	}
	for _, id := range []string{"prepare-release", "attest-release", "verify-release", "publish-release"} {
		if _, ok := order[id]; !ok {
			t.Fatalf("missing %s", id)
		}
	}
	if !(order["prepare-release"] < order["attest-release"] && order["attest-release"] < order["verify-release"] && order["verify-release"] < order["publish-release"]) {
		t.Fatal("release publication precedes attestation verification")
	}
}
func releaseFixture(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "release"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, suffix := range []string{"windows-amd64-setup.exe", "macos-amd64.dmg", "macos-arm64.dmg", "linux-amd64.deb"} {
		name := "xkeen-installer-1.2.3-" + suffix
		data := []byte("fixture:" + suffix + "\n")
		files[name] = data
		if err := os.WriteFile(filepath.Join(dir, "release", name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, files
}
func prepareReleaseFixture(t *testing.T, dir string) error {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("release fixture requires Python 3: %v", err)
	}
	cmd := exec.Command(python, "-c", provenanceRun(t, "prepare-release"))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RELEASE_TAG=v1.2.3")
	return cmd.Run()
}
func TestPrepareFinalReleasePayload(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("release job executes on Ubuntu; structural policy is tested on every OS")
	}
	for _, scenario := range []string{"valid", "missing", "extra", "directory", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			dir, files := releaseFixture(t)
			switch scenario {
			case "missing":
				os.Remove(filepath.Join(dir, "release", "xkeen-installer-1.2.3-linux-amd64.deb"))
			case "extra":
				os.WriteFile(filepath.Join(dir, "release", "extra"), []byte("extra"), 0600)
			case "directory":
				os.Remove(filepath.Join(dir, "release", "xkeen-installer-1.2.3-linux-amd64.deb"))
				os.Mkdir(filepath.Join(dir, "release", "xkeen-installer-1.2.3-linux-amd64.deb"), 0700)
			case "symlink":
				os.Remove(filepath.Join(dir, "release", "xkeen-installer-1.2.3-linux-amd64.deb"))
				os.Symlink("xkeen-installer-1.2.3-macos-arm64.dmg", filepath.Join(dir, "release", "xkeen-installer-1.2.3-linux-amd64.deb"))
			}
			err := prepareReleaseFixture(t, dir)
			if scenario != "valid" {
				if err == nil {
					t.Fatal("unsafe payload accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			sums, err := os.ReadFile(filepath.Join(dir, "release", "SHA256SUMS"))
			if err != nil {
				t.Fatal(err)
			}
			if len(strings.Split(strings.TrimSpace(string(sums)), "\n")) != 4 {
				t.Fatal("manifest does not bind exactly four installers")
			}
			for name, data := range files {
				if !strings.Contains(string(sums), fmt.Sprintf("%x  %s\n", sha256.Sum256(data), name)) {
					t.Fatal("wrong final digest")
				}
			}
		})
	}
}
func TestVerifyFinalReleasePayloadPolicyAndTampering(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("release shell executes on Ubuntu")
	}
	dir, files := releaseFixture(t)
	if err := prepareReleaseFixture(t, dir); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0700)
	log := filepath.Join(dir, "gh-argv")
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$VERIFY_LOG\"\nprintf '%s\\n' END >> \"$VERIFY_LOG\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	run := func() error {
		cmd := exec.Command("bash", "-c", provenanceRun(t, "verify-release"))
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "VERIFY_LOG="+log, "GITHUB_REPOSITORY=Arap919/Xkeen-installer", "GITHUB_SHA="+strings.Repeat("a", 40))
		return cmd.Run()
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSuffix(string(data), "END\n"), "END\n")
	if len(calls) != 5 {
		t.Fatalf("expected all five final files to be verified, got %d", len(calls))
	}
	for _, call := range calls {
		for _, required := range []string{"attestation\nverify\n", "--repo\nArap919/Xkeen-installer\n", "--cert-identity\nhttps://github.com/Arap919/Xkeen-installer/.github/workflows/build.yml@refs/heads/main\n", "--source-digest\n" + strings.Repeat("a", 40) + "\n", "--deny-self-hosted-runners\n"} {
			if !strings.Contains(call, required) {
				t.Fatalf("verification lacks identity policy: %q", required)
			}
		}
	}
	os.Remove(log)
	for name := range files {
		os.WriteFile(filepath.Join(dir, "release", name), []byte("tampered"), 0600)
		break
	}
	if run() == nil {
		t.Fatal("tampered final bytes accepted")
	}
	if _, err = os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("tampered local manifest reached attestation verification")
	}
}
