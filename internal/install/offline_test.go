package install

import (
	"context"
	"io/fs"
	"strings"
	"testing"
)

func TestFeedPolicyRejectsInsecureMissingAndDisabledTrust(t *testing.T) {
	for _, config := range []string{
		"src/gz safe https://bin.entware.net/aarch64-k3.10\n\"src/gz\" hostile \"http://example.invalid/feed\"\n",
		"src/gz safe https://bin.entware.net/aarch64-k3.10\n\"option\" no_check_certificate\n",
		"src/gz safe https://bin.entware.net/aarch64-k3.10\noption \"no_check_certificate\"\n",
		"", "src/gz entware http://bin.entware.net/aarch64-k3.10\n",
		"src/gz entware https://bin.entware.net/aarch64-k3.10\noption no_check_certificate\n",
		"src/gz entware ftp://example.invalid/repo\n",
		"src/gz entware file:///tmp/unreviewed\n",
		"src/gz entware https://user:private-secret@example.invalid/repo\n",
	} {
		err := validateFeedData([][]byte{[]byte(config)})
		if err == nil {
			t.Fatalf("unsafe feed accepted: %q", config)
		}
		if strings.Contains(err.Error(), "private-secret") {
			t.Fatal("feed credentials leaked")
		}
	}
	for _, config := range []string{
		"src/gz entware https://bin.entware.net/aarch64-k3.10\ndest root /\n",
		"src xkeen file:///opt/.xkeen-installer-repository\ndest root /\n",
	} {
		if err := validateFeedData([][]byte{[]byte(config)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnsafeFeedsStopBeforeWritesOrPackageHooks(t *testing.T) {
	f := fixture()
	f.files["/opt/etc/opkg.conf"] = []byte("src/gz entware http://example.invalid/private-secret\n")
	p := confirm(t, planFor(t, f))
	if _, err := run(context.Background(), p, f, nil, fakeLoad); err == nil {
		t.Fatal("insecure installation continued")
	}
	if f.writes != 0 {
		t.Fatal("insecure feeds were rejected after writes")
	}
	for _, command := range f.commands {
		if (strings.Contains(command, "/opt/bin/opkg") && strings.Contains(command, " update")) || (strings.Contains(command, "/opt/bin/opkg") && strings.Contains(command, " install ")) {
			t.Fatal("package command ran before feed rejection")
		}
	}
}

func TestOfflineInstallUsesOnlyPrivateRepository(t *testing.T) {
	f := fixture()
	original := append([]byte(nil), f.files["/opt/etc/opkg.conf"]...)
	p := confirm(t, planFor(t, f))
	report, err := run(context.Background(), p, f, nil, fakeLoad)
	if err != nil || !report.Complete {
		t.Fatalf("offline installation failed: %v", err)
	}
	calls := 0
	for _, command := range f.commands {
		if !strings.Contains(command, "/opt/bin/opkg") || (!strings.Contains(command, " update") && !strings.Contains(command, " install ")) {
			continue
		}
		calls++
		if !strings.HasPrefix(command, "/opt/bin/env -i PATH=") || !strings.Contains(command, "OPKG_CONF_DIR='/opt/.xkeen-installer-stage/"+p.ID+"/entware'") || !strings.Contains(command, "/opt/bin/opkg --conf '") {
			t.Fatal("package command escaped private configuration")
		}
	}
	if calls < 2 || string(original) != string(f.files["/opt/etc/opkg.conf"]) {
		t.Fatal("missing local package operations or user configuration changed")
	}
}

func TestExternalPackageCallbacksAndAdditionalHTTPFeedsFailClosed(t *testing.T) {
	for _, filename := range []string{"/opt/lib/functions.sh", "/opt/etc/opkg/custom.conf"} {
		f := fixture()
		f.files[filename] = []byte("src/gz extra http://example.invalid/repository\n")
		p := confirm(t, planFor(t, f))
		if _, err := run(context.Background(), p, f, nil, fakeLoad); err == nil || f.writes != 0 {
			t.Fatal("unreviewed callbacks or additional feed permitted writes")
		}
	}
}

type corruptOfflineWrite struct{ *fakeRouter }

func (f *corruptOfflineWrite) WriteAtomic(ctx context.Context, filename string, data []byte, mode fs.FileMode) error {
	if err := f.fakeRouter.WriteAtomic(ctx, filename, data, mode); err != nil {
		return err
	}
	if strings.Contains(filename, "/entware/") && strings.HasSuffix(filename, ".ipk") && len(f.files[filename]) > 0 {
		f.files[filename][0] ^= 1
	}
	return nil
}

func TestChangedOfflinePackageReadbackStopsBeforeOpkg(t *testing.T) {
	base := fixture()
	p := confirm(t, planFor(t, base))
	transport := &corruptOfflineWrite{base}
	if _, err := run(context.Background(), p, transport, nil, fakeLoad); err == nil {
		t.Fatal("changed package bytes accepted")
	}
	for _, command := range base.commands {
		if strings.Contains(command, "/opt/bin/opkg") && (strings.Contains(command, " update") || strings.Contains(command, " install ")) {
			t.Fatal("opkg ran after failed package readback")
		}
	}
}

func TestIncompletePackageStateAndUnknownUpgradeHooksStopBeforeWrites(t *testing.T) {
	for _, scenario := range []string{"unpacked", "half-configured", "old-hook"} {
		f := fixture()
		f.files["/opt/lib/opkg/status"] = []byte("Package: opkg\nVersion: 1\nStatus: install user installed\n\n")
		if scenario == "old-hook" {
			f.files["/opt/lib/opkg/status"] = append(f.files["/opt/lib/opkg/status"], []byte("Package: curl\nVersion: 0\nStatus: install ok installed\n\n")...)
			f.files["/opt/lib/opkg/info/curl.prerm"] = []byte("#!/bin/sh\ntouch /opt/fixture-hook-must-not-run\n")
		} else {
			f.files["/opt/lib/opkg/status"] = append(f.files["/opt/lib/opkg/status"], []byte("Package: unrelated-fixture\nVersion: 1\nStatus: install ok "+scenario+"\n\n")...)
			f.files["/opt/lib/opkg/info/unrelated-fixture.postinst"] = []byte("#!/bin/sh\ntouch /opt/fixture-hook-must-not-run\n")
		}
		p := confirm(t, planFor(t, f))
		if _, err := run(context.Background(), p, f, nil, fakeLoad); err == nil || f.writes != 0 {
			t.Fatalf("unsafe package state reached mutation: %s", scenario)
		}
	}
}

func TestFreshCredentialPackagesNeverReachExistingInstall(t *testing.T) {
	for _, name := range []string{"dropbear", "opt-ndmsv2"} {
		f := fixture()
		if err := inspectPackageState(context.Background(), f, map[string]string{name: "1"}); err == nil {
			t.Fatalf("fresh-only credential package selected: %s", name)
		}
		if f.writes != 0 {
			t.Fatal("existing credentials changed before rejection")
		}
	}
}
