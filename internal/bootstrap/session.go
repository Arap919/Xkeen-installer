package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"sync"
	"time"
)

type CLI interface {
	RunCLI(context.Context, string) ([]byte, error)
}
type Store interface {
	Check(context.Context, Volume, catalog.Artifact) error
	Publish(context.Context, Volume, catalog.Artifact, []byte) error
	PublishCredential(context.Context, Volume, catalog.Artifact, []byte) error
	CheckCredential(context.Context, Volume, catalog.Artifact, []byte) error
}
type Plan struct {
	ID              string
	Model           string
	Hardware        string
	Arch            catalog.RouterArch
	Volume          Volume
	Archive         string
	URL             string
	SHA256          string
	Size            int64
	Commands        []string
	IntegritySource string
}
type Session struct {
	mu         sync.Mutex
	cli        CLI
	store      Store
	plan       Plan
	credential []byte
	snapshot   Snapshot
	prepared   time.Time
	download   func(context.Context, catalog.Artifact) ([]byte, error)
}

var ErrTriggerUncertain = errors.New("firmware trigger may have executed; inspect before retry")

func NewSession(cli CLI, store Store) *Session {
	return &Session{cli: cli, store: store, download: Download}
}
func Inspect(ctx context.Context, cli CLI) (Snapshot, error) {
	version, e := cli.RunCLI(ctx, "show version")
	if e != nil {
		return Snapshot{}, &DiscoveryError{Stage: "show version", cause: e}
	}
	media, e := cli.RunCLI(ctx, "show media")
	if e != nil {
		return Snapshot{}, &DiscoveryError{Stage: "show media", cause: e}
	}
	config, e := cli.RunCLI(ctx, "show running-config")
	if e != nil {
		return Snapshot{}, &DiscoveryError{Stage: "show running-config", cause: e}
	}
	s, e := Parse(string(version), string(media), string(config))
	clear(config)
	if e != nil {
		return Snapshot{}, &DiscoveryError{Stage: "parse", cause: e}
	}
	cifs, e := cli.RunCLI(ctx, "show cifs")
	if e != nil {
		return Snapshot{}, &DiscoveryError{Stage: "show cifs", cause: e}
	}
	s, e = withCIFS(s, string(cifs))
	if e != nil {
		return Snapshot{}, &DiscoveryError{Stage: "parse cifs", cause: e}
	}
	return s, nil
}
func (s *Session) Prepare(ctx context.Context, uuid, password, repeat string) (Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plan = Plan{}
	clear(s.credential)
	s.credential = nil
	if e := ValidatePassword(password, repeat); e != nil {
		return Plan{}, e
	}
	snap, e := Inspect(ctx, s.cli)
	if e != nil {
		return Plan{}, e
	}
	v, e := snap.Select(uuid)
	if e != nil {
		return Plan{}, e
	}
	a, e := catalog.Resolve(catalog.Entware, snap.Arch)
	if e != nil || a.Size == 0 || a.Integrity.SHA256 == "" {
		return Plan{}, ErrUnsafe
	}
	if e = s.store.Check(ctx, v, a); e != nil {
		return Plan{}, ErrUnsafe
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return Plan{}, ErrUnsafe
	}
	commands := []string{}
	if snap.disk != "" {
		commands = append(commands, "no opkg disk")
	}
	commands = append(commands, "opkg initrc /opt/etc/init.d", "opkg disk "+v.UUID+":/")
	s.plan = Plan{ID: hex.EncodeToString(id[:]), Model: snap.Model, Hardware: snap.Hardware, Arch: snap.Arch, Volume: v, Archive: archiveName(a.Arch), URL: a.URL, SHA256: a.Integrity.SHA256, Size: a.Size, Commands: commands, IntegritySource: a.Integrity.Source}
	hash, e := NewPasswordHash(password, repeat)
	password = ""
	repeat = ""
	if e != nil {
		s.plan = Plan{}
		return Plan{}, e
	}
	s.credential, e = makeCredential(s.plan.ID, v, a, hash)
	hash = ""
	if e != nil {
		s.plan = Plan{}
		return Plan{}, e
	}
	s.snapshot = snap
	s.prepared = time.Now()
	return s.plan, nil
}

// KeeneticOS documents native processing of *.tgz. This changes only the
// destination filename; reviewed offline bundle bytes and their digest stay intact.
func archiveName(arch catalog.RouterArch) string {
	if arch == catalog.ARM64 {
		return "aarch64-installer.tgz"
	}
	return string(arch) + "-installer.tgz"
}
func (s *Session) recheck(ctx context.Context, p Plan) error {
	snap, e := Inspect(ctx, s.cli)
	if e != nil {
		return e
	}
	v, e := snap.Select(p.Volume.UUID)
	if e != nil || snap.Hardware != s.snapshot.Hardware || snap.Arch != s.snapshot.Arch || snap.disk != s.snapshot.disk || snap.initrc != s.snapshot.initrc || v.Share != p.Volume.Share || v.MediaID != p.Volume.MediaID {
		return ErrUnsafe
	}
	return nil
}
func (s *Session) Start(ctx context.Context, id string, reviewed bool, progress func(string)) (failure error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reviewed || id == "" || id != s.plan.ID || time.Since(s.prepared) > 5*time.Minute {
		return ErrUnsafe
	}
	p := s.plan
	s.plan = Plan{} // Every reviewed attempt consumes its approval, including invalid private state.
	credential := s.credential
	s.credential = nil
	defer clear(credential)
	if !validCredentialPayload(credential) {
		return ErrUnsafe
	}
	currentStage := "reinspect"
	defer func() {
		if failure != nil {
			failure = &StartError{Stage: currentStage, cause: failure}
		}
	}()
	stage := func(v string) {
		currentStage = v
		if progress != nil {
			progress(v)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	stage("reinspect")
	if e := s.recheck(ctx, p); e != nil {
		return e
	}
	a, e := catalog.Resolve(catalog.Entware, p.Arch)
	if e != nil {
		return ErrUnsafe
	}
	stage("download")
	data, e := s.download(ctx, a)
	if e != nil {
		return e
	}
	defer clear(data)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	stage("pre-transfer-inspect")
	if e = s.recheck(ctx, p); e != nil {
		return e
	}
	stage("store-check")
	if e = s.store.Check(ctx, p.Volume, a); e != nil {
		return ErrUnsafe
	}
	stage("transfer")
	if e = s.store.Publish(ctx, p.Volume, a, data); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	stage("credential-transfer")
	if e = s.store.PublishCredential(ctx, p.Volume, a, credential); e != nil {
		return e
	}
	stage("post-transfer-inspect")
	if e = s.recheck(ctx, p); e != nil {
		return e
	}
	stage("post-transfer-store-check")
	if e = s.store.Check(ctx, p.Volume, a); e != nil {
		return ErrUnsafe
	}
	stage("credential-check")
	if e = s.store.CheckCredential(ctx, p.Volume, a, credential); e != nil {
		return e
	}
	stage("trigger")
	for _, command := range p.Commands {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, e = s.cli.RunCLI(ctx, command); e != nil {
			return ErrTriggerUncertain
		}
	}
	stage("waiting-shell")
	return nil
}
