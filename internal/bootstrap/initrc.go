package bootstrap

import "context"

// FinalInitrc verifies firmware state after the native installer has taken over.
// The temporary directory is an installation mechanism, never a readiness result.
func FinalInitrc(ctx context.Context, cli CLI) error {
	config, e := cli.RunCLI(ctx, "show running-config")
	if e != nil {
		return ErrUnsafe
	}
	defer clear(config)
	commands, e := configurationTokens(string(config))
	if e != nil {
		return e
	}
	count := 0
	for _, f := range commands {
		if len(f) >= 2 && f[0] == "opkg" && f[1] == "initrc" {
			if len(f) != 3 || f[2] != "/opt/etc/init.d/rc.unslung" {
				return ErrUnsafe
			}
			count++
		}
	}
	if count != 1 {
		return ErrUnsafe
	}
	return nil
}
