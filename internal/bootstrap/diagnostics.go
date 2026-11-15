package bootstrap

// DiscoveryError identifies the failed read-only stage without serializing CLI output.
// The original cause remains available only through Go error inspection.
type DiscoveryError struct {
	Stage string
	cause error
}

func (e *DiscoveryError) Error() string   { return "firmware discovery failed at " + e.Stage }
func (e *DiscoveryError) Unwrap() []error { return []error{ErrUnsafe, e.cause} }

// StartError identifies a failed stage without exposing remote output.
type StartError struct {
	Stage string
	cause error
}

func (e *StartError) Error() string { return "Entware bootstrap failed at " + e.Stage }
func (e *StartError) Unwrap() error { return e.cause }
