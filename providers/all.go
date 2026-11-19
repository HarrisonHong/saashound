// Package providers links every platform provider into the binary. Adding a
// platform is one import line here; nothing else in the core changes.
package providers

import (
	// The simulated platform used by the test suites and `--target <fake>`.
	_ "github.com/HarrisonHong/saashound/providers/fake"
	// Okta: the first real platform.
	_ "github.com/HarrisonHong/saashound/providers/okta"
)
