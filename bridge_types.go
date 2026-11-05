package main

import (
	"context"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/install"
	"github.com/Arap919/xkeen-installer/internal/router"
	localtls "github.com/Arap919/xkeen-installer/internal/tls"
	"github.com/Arap919/xkeen-installer/internal/verify"
	"sync"
	"time"
)

// Requests are transient inputs, never persisted or included in reports.
type ConnectionRequest struct {
	Host     string
	Port     int
	User     string
	Password string
}

func (ConnectionRequest) String() string     { return "ConnectionRequest{redacted}" }
func (c ConnectionRequest) GoString() string { return c.String() }

type HostKeyView struct {
	Kind        string
	Address     string
	Fingerprint string
	Expected    string
	Algorithm   string
}
type InspectionView struct {
	ID         string
	Arch       string
	Entware    bool
	Available  uint64
	ActiveCore string
	Versions   map[string]string
	HostKey    *HostKeyView
}
type PlanRequest struct {
	InspectionID string
	Cores        []string
	ActiveCore   string
	UI           bool
	Watchdog     bool
	ImportCore   string
	ImportText   string
	ProviderURL  string
}

func (PlanRequest) String() string     { return "PlanRequest{redacted}" }
func (p PlanRequest) GoString() string { return p.String() }

type ArtifactView struct {
	Component string
	Version   string
}
type PlanView struct {
	ID           string
	Steps        []install.Step
	Changes      []install.FileChange
	Artifacts    []ArtifactView
	Dependencies []string
	Notes        []string
	Files        []config.FilePreview
	Conflicts    []config.Conflict
	Message      string
}
type Progress struct {
	Step    string
	Status  string
	Message string
}
type ResultView struct {
	Status            string
	Message           string
	Backup            string
	Completed         []string
	Applied           []string
	Uncertain         string
	Pending           []string
	PanelURL          string
	Services          []verify.ServiceReport
	ReinspectRequired bool
}
type TrustView struct {
	ID          string
	Description string
	Manual      string
}

// App is the only bound object. Backend plans, TLS keys and config bytes stay private.
type App struct {
	mu           sync.Mutex
	ctx          context.Context
	transport    router.Transport
	snapshot     router.Snapshot
	snapshotID   string
	inspectedAt  time.Time
	address      string
	hostKeys     map[string]string
	pendingHost  *HostKeyView
	plan         install.Plan
	proposal     config.ConfigProposal
	planSnapshot string
	confirmed    bool
	busy         bool
	cancel       context.CancelFunc
	tls          localtls.TLSProposal
	tlsDir       string
	trust        localtls.TrustAction
	result       ResultView
	run          func(context.Context, install.Plan, router.Transport, func(install.Event)) (install.Report, error)
	confirm      func(install.Plan, string) (install.Plan, error)
	emit         func(Progress)
}

func newApp() *App {
	return &App{ctx: context.Background(), hostKeys: map[string]string{}, run: install.Run, confirm: install.ConfirmPlan, emit: func(Progress) {}}
}
