package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// printRows prints left-aligned columns separated by two spaces.
func printRows(w io.Writer, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) {
				widths[i] = max(widths[i], len(c))
			}
		}
	}
	for _, r := range rows {
		var b strings.Builder
		for i, c := range r {
			b.WriteString(c)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-len(c)+2))
			}
		}
		fmt.Fprintln(w, b.String())
	}
}

func sortStrings(s []string) { sort.Strings(s) }
