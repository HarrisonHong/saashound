// Command saashound runs documented SaaS and identity-provider intrusion
// techniques against a tenant you own, proves cleanup, and reports whether
// the platform logged each technique and whether your detection fired.
package main

import (
	"context"
	"os"

	"github.com/HarrisonHong/saashound/internal/cli"
	_ "github.com/HarrisonHong/saashound/providers" // link every provider
)

func main() {
	os.Exit(cli.Main(context.Background(), os.Args[1:], cli.OSEnv()))
}
