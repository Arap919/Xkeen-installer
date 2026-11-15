package bootstrap

import (
	"context"
	"errors"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"strings"
	"testing"
)

type fixtureCLI struct {
	version string
	config  string
	media   string
	cifs    string
	writes  int
}

func (c *fixtureCLI) RunCLI(ctx context.Context, command string) ([]byte, error) {
	switch command {
	case "show version":
		if c.version != "" {
			return []byte(c.version), nil
		}
		return []byte("hw_id: KN-2410\nmodel: Ultra\narch: mips\n"), nil
	case "show media":
		return []byte(c.media), nil
	case "show running-config":
		return []byte(c.config), nil
	case "show cifs":
		if c.cifs != "" {
			return []byte(c.cifs), nil
		}
		return []byte("enabled: yes\nshare:\n mount: 12345678-abcd-1234-abcd-123456789abc:\n label: ENTWARE\n active: yes\n"), nil
	default:
		c.writes++
		return nil, nil
	}
}

type fixtureStore struct {
	published    int
	checks       int
	afterPublish func()
}

func (s *fixtureStore) Check(context.Context, Volume, catalog.Artifact) error { s.checks++; return nil }
func (s *fixtureStore) Publish(context.Context, Volume, catalog.Artifact, []byte) error {
	s.published++
	if s.afterPublish != nil {
		s.afterPublish()
	}
	return nil
}
func TestReviewedBootstrapOneShotAndLateDiskCheck(t *testing.T) {
	ctx := context.Background()
	c := &fixtureCLI{config: "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/", media: mediaFixture}
	store := &fixtureStore{}
	s := NewSession(c, store)
	p, err := s.Prepare(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(ctx, p.ID, false, nil); err == nil || store.published != 0 {
		t.Fatal("unreviewed plan wrote")
	}
	c.config += "\nopkg disk other:/"
	if err = s.Start(ctx, p.ID, true, nil); err == nil || store.published != 0 || c.writes != 0 {
		t.Fatal("late disk state ignored")
	}
	if err = s.Start(ctx, p.ID, true, nil); err == nil {
		t.Fatal("consumed plan reusable")
	}
}
func TestBootstrapStopsOnVolumeChangeAfterTransferAndCancellation(t *testing.T) {
	for _, kind := range []string{"uuid", "media", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &fixtureCLI{config: "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/", media: mediaFixture}
			st := &fixtureStore{}
			s := NewSession(c, st)
			s.download = func(context.Context, catalog.Artifact) ([]byte, error) {
				return []byte("fixture download boundary"), nil
			}
			p, e := s.Prepare(ctx, "")
			if e != nil {
				t.Fatal(e)
			}
			st.afterPublish = func() {
				switch kind {
				case "uuid":
					c.media = strings.ReplaceAll(c.media, "12345678-abcd-1234-abcd-123456789abc", "11111111-abcd-1234-abcd-123456789abc")
				case "media":
					c.media = strings.ReplaceAll(c.media, "name: USB", "name: OTHER")
				case "cancel":
					cancel()
				}
			}
			if e = s.Start(ctx, p.ID, true, nil); e == nil || c.writes != 0 || st.published != 1 {
				t.Fatalf("unsafe trigger: %v writes=%d transferred=%d", e, c.writes, st.published)
			}
			if e = s.Start(ctx, p.ID, true, nil); e == nil {
				t.Fatal("failure reused consumed plan")
			}
		})
	}
}
func TestBootstrapSelectedSameDiskShowsDetachAndRebind(t *testing.T) {
	c := &fixtureCLI{config: "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/\nopkg disk 12345678-abcd-1234-abcd-123456789abc:/", media: mediaFixture}
	s := NewSession(c, &fixtureStore{})
	p, e := s.Prepare(context.Background(), "")
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Commands) != 3 || p.Commands[0] != "no opkg disk" || p.Commands[1] != "opkg initrc /opt/etc/init.d" || p.Commands[2] != "opkg disk 12345678-abcd-1234-abcd-123456789abc:/" {
		t.Fatal(p.Commands)
	}
}

type failingPublishStore struct{ fixtureStore }

func (s *failingPublishStore) Publish(context.Context, Volume, catalog.Artifact, []byte) error {
	return errors.New("private SMB failure")
}
func TestBootstrapFailureRetainsExactStage(t *testing.T) {
	c := &fixtureCLI{config: "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/", media: mediaFixture}
	s := NewSession(c, &failingPublishStore{})
	s.download = func(context.Context, catalog.Artifact) ([]byte, error) { return []byte("fixture"), nil }
	p, e := s.Prepare(context.Background(), "")
	if e != nil {
		t.Fatal(e)
	}
	e = s.Start(context.Background(), p.ID, true, nil)
	var failure *StartError
	if !errors.As(e, &failure) || failure.Stage != "transfer" {
		t.Fatalf("missing transfer stage: %v", e)
	}
	if strings.Contains(e.Error(), "private") {
		t.Fatal("private cause leaked")
	}
	if c.writes != 0 {
		t.Fatal("triggered OPKG after failed transfer")
	}
}
