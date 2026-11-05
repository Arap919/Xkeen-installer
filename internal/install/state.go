// Package install builds reviewed backend plans and executes bounded, serial router changes.
package install

import (
	"encoding/json"
	"errors"
	"io/fs"
	"sync/atomic"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
	localtls "github.com/Arap919/xkeen-installer/internal/tls"
)

var (
	ErrUnconfirmed = errors.New("План необходимо явно подтвердить после просмотра")
	ErrConsumed    = errors.New("План уже запускался; повторите проверку и создайте новый план")
	ErrStale       = errors.New("Состояние роутера изменилось; повторите проверку и просмотр плана")
)

type Selection struct {
	Config config.Selection
	UI     bool
}
type Step struct {
	ID          string
	Description string
}
type FileChange struct {
	Path   string
	Action string
	Mode   string
}
type Plan struct {
	Changes      []FileChange
	ID           string
	Steps        []Step
	Artifacts    []catalog.Artifact
	Dependencies []string
	ActiveCore   catalog.Component
	Notes        []string
	private      *planData
	confirmed    bool
}
type planData struct {
	tls              localtls.TLSProposal
	preview          string
	fingerprint      [32]byte
	snapshot         router.Snapshot
	selection        Selection
	configs          []payload
	artifacts        []catalog.Artifact
	active           catalog.Component
	uiPort           int
	existingInit     []byte
	existingInitMode fs.FileMode
	configuredCore   catalog.Component
	pending          []string
	used             atomic.Bool
}
type Event struct {
	Step   string
	Status string
}

// Complete means all reviewed operations finished; Pending still describes components
// deliberately not activated (for example, a new UI awaiting the later TLS task).
type Report struct {
	Complete          bool
	Backup            router.BackupManifest
	Applied           []string
	UncertainPath     string
	Completed         []string
	Uncertain         string
	Pending           []string
	ReinspectRequired bool
}

func (p Plan) String() string     { b, _ := json.Marshal(p); return string(b) }
func (p Plan) GoString() string   { return p.String() }
func (r Report) String() string   { b, _ := json.Marshal(r); return string(b) }
func (r Report) GoString() string { return r.String() }
func publicPlan(p Plan) string    { b, _ := json.Marshal(p); return string(b) }

// ConfirmPlan is a backend-only approval boundary. The caller must first show this
// exact preview and obtain the user's affirmative action; JSON cannot mint a plan.
func ConfirmPlan(p Plan, reviewedID string) (Plan, error) {
	if p.private == nil || p.ID == "" || reviewedID != p.ID || p.private.preview != publicPlan(p) {
		return Plan{}, ErrUnconfirmed
	}
	if p.private.used.Load() {
		return Plan{}, ErrConsumed
	}
	p.confirmed = true
	return p, nil
}
