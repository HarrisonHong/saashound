// Package version holds the tool's version identifiers.
package version

import "runtime/debug"

// Version is the tool version. Release builds set it with
// -ldflags "-X github.com/HarrisonHong/saashound/internal/version.Version=v0.1.0".
var Version = ""

// Tool is the tool name as it appears in output records and User-Agents.
const Tool = "saashound"

// String returns the effective version: the ldflags value, else the module
// version recorded by `go install`, else "0.0.0-dev".
func String() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "0.0.0-dev"
}

// ToolString is "saashound/<version>".
func ToolString() string { return Tool + "/" + String() }
