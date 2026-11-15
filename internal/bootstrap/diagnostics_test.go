package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type failingDiscoveryCLI struct {
	fixtureCLI
	command string
}

func (c *failingDiscoveryCLI) RunCLI(ctx context.Context, command string) ([]byte, error) {
	if command == c.command {
		return nil, errors.New("private-password configuration-secret")
	}
	return c.fixtureCLI.RunCLI(ctx, command)
}
func TestDiscoveryReportsFailedCommandWithoutRemoteOutput(t *testing.T) {
	for _, command := range []string{"show version", "show media", "show running-config", "show cifs"} {
		c := &failingDiscoveryCLI{fixtureCLI: fixtureCLI{media: mediaFixture}, command: command}
		_, err := Inspect(context.Background(), c)
		var stage *DiscoveryError
		if !errors.As(err, &stage) || stage.Stage != command {
			t.Fatalf("wrong stage for %s: %v", command, err)
		}
		if !errors.Is(err, ErrUnsafe) || strings.Contains(err.Error(), "private-password") || strings.Contains(err.Error(), "configuration-secret") {
			t.Fatal("unsafe stage error")
		}
	}
}
