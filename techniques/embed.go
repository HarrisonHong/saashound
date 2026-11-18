// Package techniques embeds the verified technique corpus into the binary.
// A release therefore pins an exact, tested corpus version, and signing the
// binary signs the corpus.
//
// Each platform's techniques live in their own directory, named after the
// provider, so CODEOWNERS can assign them to whoever maintains that platform.
package techniques

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed VERSION */*.yaml
var files embed.FS

// FS returns the embedded corpus.
func FS() fs.FS { return files }

// Version returns the corpus version.
func Version() string {
	b, err := files.ReadFile("VERSION")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}
