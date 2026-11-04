package router

import (
	"context"
	"errors"
	"testing"
)

type evidenceTransport struct {
	*fakeTransport
	processes   string
	failCommand string
	failure     error
}

func (f evidenceTransport) Run(ctx context.Context, c string) (Result, error) {
	if c == f.failCommand {
		return Result{}, f.failure
	}
	if c == activeCoreProbe {
		return Result{Stdout: []byte(f.processes)}, nil
	}
	return f.fakeTransport.Run(ctx, c)
}
func TestInspectActiveCoreEvidenceAndUnknownVersions(t *testing.T) {
	for _, tc := range []struct{ ps, want string }{{"123 root /opt/sbin/mihomo -f /opt/etc/mihomo/config.yaml", "mihomo"}, {"124 root /opt/sbin/xray run -confdir /opt/etc/xray/configs", "xray"}, {"123 root /opt/sbin/xray\n124 root /opt/sbin/mihomo", "unknown"}, {"123 root grep mihomo", "unknown"}, {"123 root grep /opt/sbin/mihomo", "unknown"}, {"PID USER VSZ STAT COMMAND\n123 root 1000 S /opt/sbin/mihomo -f config", "mihomo"}} {
		t.Run(tc.want+tc.ps[:3], func(t *testing.T) {
			s, err := Inspect(context.Background(), evidenceTransport{fakeTransport: fixture(), processes: tc.ps})
			if err != nil {
				t.Fatal(err)
			}
			if s.ActiveCore != tc.want {
				t.Fatalf("active=%q want %q", s.ActiveCore, tc.want)
			}
			if s.Versions["opkg"] != "1" || s.Versions["xray"] != "unknown" || s.Versions["mihomo"] != "unknown" || s.Versions["xkeen"] != "unknown" {
				t.Fatal("unestablished standalone versions must remain explicit", s.Versions)
			}
			m, err := Backup(context.Background(), fixture(), s)
			if err != nil {
				t.Fatal(err)
			}
			if m.ActiveCore != s.ActiveCore || m.Versions["xray"] != "unknown" {
				t.Fatal("backup lost evidence")
			}
		})
	}
}
func TestInspectPreservesCancellationAtCommandBoundaries(t *testing.T) {
	for _, command := range []string{shellProbe, archProbe, endianProbe, versionProbe, activeCoreProbe} {
		for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
			f := fixture()
			f.arch = "mips"
			_, err := Inspect(context.Background(), evidenceTransport{fakeTransport: f, failCommand: command, failure: want})
			if !errors.Is(err, want) {
				t.Fatalf("command %q: got %v, want %v", command, err, want)
			}
		}
	}
}

func TestOwnedXkeenHooksIncludedInBackupInventory(t *testing.T) {
	f := fixture()
	f.files["/opt/etc/ndm/netfilter.d/proxy.sh"] = []byte("owned-hook")
	f.files["/opt/etc/ndm/netfilter.d/unrelated.sh"] = []byte("unrelated")
	f.files["/opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh"] = []byte("owned-schedule")
	s, e := Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"/opt/etc/ndm/netfilter.d/proxy.sh", "/opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh"} {
		if _, ok := s.Config(p); !ok {
			t.Fatal("owned hook omitted", p)
		}
	}
	if _, ok := s.Config("/opt/etc/ndm/netfilter.d/unrelated.sh"); ok {
		t.Fatal("unrelated hook included")
	}
}
