package install

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arap919/xkeen-installer/internal/bootstrap"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"golang.org/x/crypto/ssh"
)

func TestNativeFirstAccess(t *testing.T) {
	arch := catalog.RouterArch(os.Getenv("XKEEN_OFFLINE_FIXTURE_ARCH"))
	if arch == "" {
		t.Skip("requires isolated SEC-007 fixture")
	}
	if b, e := os.ReadFile("/fixture-isolated"); e != nil || string(b) != "SEC001_NETWORK_NONE\n" {
		t.Fatal("isolated marker required")
	}
	if arch != catalog.ARM64 && arch != catalog.MIPS && arch != catalog.MIPSel {
		t.Fatal("invalid fixture architecture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	n := nativeOfflineFixture{arch: arch}
	run := func(s string) bool { r, e := n.Run(ctx, s); return e == nil && r.ExitCode == 0 }
	gate := "/opt/bin/sh /opt/etc/xkeen-first-access "
	if run(gate + "verify") {
		t.Fatal("missing ready accepted")
	}
	password := "Fixture-only-strong-password-2026!"
	hash, e := bootstrap.NewPasswordHash(password, password)
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte("XKEEN-BOOTSTRAP-V1\n" + strings.Repeat("a", 32) + "\n12345678-abcd-1234-abcd-123456789abc\n" + string(arch) + "\n" + strings.Repeat("b", 64) + "\n" + hash + "\n")
	if e = os.WriteFile("/opt/.xkeen-bootstrap-credential", payload, 0600); e != nil {
		t.Fatal(e)
	}
	if !run("PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin /opt/bin/sh /opt/bin/install") {
		t.Fatal("fresh bootstrap failed; private output suppressed")
	}
	if !run(gate + "verify") {
		t.Fatal("complete bootstrap not ready")
	}
	if _, e = os.Stat("/opt/.xkeen-bootstrap-credential"); !os.IsNotExist(e) {
		t.Fatal("transferable hash retained")
	}
	// The normal init path must also work, and be stopped before isolated auth.
	if !run("/opt/etc/init.d/S51dropbear start") {
		t.Fatal("ready init rejected")
	}
	run("/opt/etc/init.d/S51dropbear stop")
	address, stopAuth := firstAccessAuthListener(t, ctx, arch, gate)
	defer stopAuth()
	for _, attempt := range []struct {
		password string
		accept   bool
	}{{"keenetic", false}, {"Incorrect-fixture-password!", false}, {password, true}} {
		conn, e := net.DialTimeout("tcp", address, 5*time.Second)
		if e != nil {
			t.Fatal("isolated SSH connect failed")
		}
		conn.SetDeadline(time.Now().Add(90 * time.Second))
		client, chans, reqs, e := ssh.NewClientConn(conn, address, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password(attempt.password)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 90 * time.Second})
		accepted := e == nil
		if accepted {
			ssh.NewClient(client, chans, reqs).Close()
		} else {
			conn.Close()
		}
		if !attempt.accept && e != nil && !strings.Contains(e.Error(), "unable to authenticate") {
			t.Fatalf("SSH failed before password authentication: %v", e)
		}
		if accepted != attempt.accept {
			t.Fatalf("SSH authentication result mismatch: expected accept=%v", attempt.accept)
		}
	}
	stopAuth()
	// Interrupt precisely after passwd publication, while keygen is running.
	// The old shared EXIT/TERM cleanup trap continued and published ready.
	interruptedKeygen := "/opt/bin/dropbearkey"
	if e = os.Rename(interruptedKeygen, interruptedKeygen+".fixture-signal-original"); e != nil {
		t.Fatal(e)
	}
	wrapper := []byte("#!/opt/bin/sh\nkill -TERM \"$PPID\"\nexec -a dropbearkey /opt/bin/dropbearkey.fixture-signal-original \"$@\"\n")
	if e = os.WriteFile(interruptedKeygen, wrapper, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/opt/.xkeen-bootstrap-credential", payload, 0600); e != nil {
		t.Fatal(e)
	}
	configured := run(gate + "configure")
	os.Remove(interruptedKeygen)
	if e = os.Rename(interruptedKeygen+".fixture-signal-original", interruptedKeygen); e != nil {
		t.Fatal(e)
	}
	if configured || run(gate+"verify") || run("/opt/etc/init.d/S51dropbear start") {
		t.Fatal("TERM during keygen published readiness")
	}
	if !run(gate+"configure") || !run(gate+"verify") {
		t.Fatal("interrupted setup could not complete safely")
	}
	passwd, e := os.ReadFile("/opt/etc/passwd")
	if e != nil {
		t.Fatal(e)
	}
	// Stale readiness cannot survive an account overwrite or host-key change.
	os.WriteFile("/opt/etc/passwd", []byte("root:locked:0:0:root:/opt/root:/opt/bin/sh\n"), 0600)
	if run(gate+"verify") || run("/opt/etc/init.d/S51dropbear start") {
		t.Fatal("stale account readiness accepted")
	}
	os.WriteFile("/opt/etc/passwd", passwd, 0600)
	key := "/opt/etc/dropbear/dropbear_ed25519_host_key"
	keyBytes, e := os.ReadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(key, []byte("overwritten"), 0600)
	if run(gate+"verify") || run("/opt/etc/init.d/S51dropbear start") {
		t.Fatal("stale host-key readiness accepted")
	}
	os.WriteFile(key, keyBytes, 0600)
	if !run(gate + "verify") {
		t.Fatal("restored exact ready state rejected")
	}
	if !run(gate+"revoke") || run(gate+"verify") || run("/opt/etc/init.d/S51dropbear start") {
		t.Fatal("revocation did not close startup")
	}
	if run(gate + "configure") {
		t.Fatal("missing credential reopened startup")
	}
	// A partially configured fresh volume cannot publish readiness if keygen fails.
	if e = os.WriteFile("/opt/.xkeen-bootstrap-credential", payload, 0600); e != nil {
		t.Fatal(e)
	}
	keygen := "/opt/bin/dropbearkey"
	if e = os.Rename(keygen, keygen+".fixture-original"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keygen, []byte("#!/opt/bin/sh\nexit 1\n"), 0700); e != nil {
		t.Fatal(e)
	}
	if run(gate+"configure") || run(gate+"verify") || run("/opt/etc/init.d/S51dropbear start") {
		t.Fatal("failed keygen opened SSH")
	}
	os.Remove(keygen)
	if e = os.Rename(keygen+".fixture-original", keygen); e != nil {
		t.Fatal(e)
	}
	// Manual completion with the original verified sidecar succeeds; it does not
	// require enabling the default password or bypassing the gate.
	if !run(gate+"configure") || !run(gate+"verify") {
		t.Fatal("safe interrupted configuration could not complete")
	}
	t.Log("fresh bootstrap and real SSH auth accepted intended password; default/wrong rejected; stale/missing readiness fails closed")
}

// firstAccessAuthListener uses the exact target daemon. MIPS authentication runs
// directly under QEMU: proot loses the per-connection reexec before authentication.
// QEMU reports fexecve Exec format error and the unchanged Dropbear binary uses
// its supported fork fallback. Native reexec is therefore not validated on MIPS.
// Gated bootstrap and the normal init/start path still run under proot above.
func firstAccessAuthListener(t *testing.T, ctx context.Context, arch catalog.RouterArch, gate string) (string, func()) {
	t.Helper()
	daemonCtx, daemonCancel := context.WithCancel(ctx)
	program := "/opt/sbin/dropbear"
	args := []string{"-F", "-E", "-p", "127.0.0.1:3333", "-P", "/opt/var/run/fixture-dropbear.pid"}
	fixture := nativeOfflineFixture{arch: arch}
	checked, err := fixture.Run(ctx, gate+"verify")
	if err != nil || checked.ExitCode != 0 {
		daemonCancel()
		t.Fatal("readiness invalid before authentication")
	}
	if arch != catalog.ARM64 {
		program = "/usr/bin/qemu-" + string(arch) + "-static"
		args = append([]string{"/opt/sbin/dropbear"}, args...)
	}
	child := exec.CommandContext(daemonCtx, program, args...)
	if err := child.Start(); err != nil {
		daemonCancel()
		t.Fatal("daemon could not start")
	}
	var once sync.Once
	stop := func() { once.Do(func() { daemonCancel(); child.Wait() }) }
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(3333))
	deadline := time.Now().Add(15 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatal("daemon did not listen")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return address, stop
}
