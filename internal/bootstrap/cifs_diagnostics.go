package bootstrap

import "fmt"

// CIFSParseError contains only schema metadata, never response values or text.
type CIFSParseError struct {
	Reason string
	Line   int
	Field  string
}

func (e *CIFSParseError) Diagnostic() string {
	reason := "SCHEMA"
	switch e.Reason {
	case "TEXT", "CONTROL", "VALUE", "MISSING", "DUPLICATE", "CONTEXT", "UNKNOWN_FIELD", "NAME_CONFLICT", "ROOT_CONFLICT":
		reason = e.Reason
	}
	field := "unknown"
	switch e.Field {
	case "none", "share", "enabled", "automount", "permissive", "map-hidden", "master", "mount", "label", "active", "description":
		field = e.Field
	}
	line := e.Line
	if line < 0 || line > 1000000 {
		line = 0
	}
	return fmt.Sprintf("CIFS/%s/%d/%s", reason, line, field)
}
func (e *CIFSParseError) Error() string { return "CIFS response rejected: " + e.Diagnostic() }
func (e *CIFSParseError) Unwrap() error { return ErrUnsafe }
