#!/bin/sh
# Writes the license and notice texts of everything linked into the saashound
# binary to the file named by its argument: the Go runtime and standard
# library, and every third-party module on any release platform. Release
# archives ship this file beside LICENSE, as those licenses require of binary
# distributions. It fails if a linked module has no license file, so a new
# dependency cannot ship without its notice.
set -eu
export LC_ALL=C # byte-order sorting: the same output on every machine

out=${1:?usage: scripts/third-party-licenses.sh <output-file>}
case $out in
/*) ;;
*) out=$PWD/$out ;;
esac
cd "$(dirname "$0")/.."

main=$(go list -m)
mods=$(for goos in linux darwin windows; do
	GOOS=$goos go list -deps -f '{{with .Module}}{{.Path}} {{.Version}} {{.Dir}}{{end}}' ./cmd/saashound
done | grep -v "^$main " | sort -u)

mkdir -p "$(dirname "$out")"
tmp=$(mktemp "$out.XXXXXX")
trap 'rm -f "$tmp"' EXIT

rule='================================================================================'

# section <title> <file>...
section() {
	title=$1
	shift
	for f in "$@"; do
		printf '%s\n%s - %s\n%s\n\n' "$rule" "$title" "${f##*/}" "$rule"
		cat "$f"
		printf '\n'
	done >>"$tmp"
}

printf 'Third-party software linked into saashound, with the license texts its\nauthors require binary distributions to carry.\n\n' >"$tmp"
section "Go $(go env GOVERSION) (runtime and standard library)" "$(go env GOROOT)/LICENSE"

printf '%s\n' "$mods" | while read -r path version dir; do
	files=$(find "$dir" -maxdepth 1 -type f \( -iname 'licen[cs]e*' -o -iname 'copying*' -o -iname 'notice*' \) | sort)
	if [ -z "$files" ]; then
		echo "third-party-licenses: $path $version has no license file in $dir" >&2
		exit 1
	fi
	# Module cache paths hold no newlines, so split the list on newlines only.
	IFS='
'
	# shellcheck disable=SC2086 # the word splitting is deliberate
	section "$path $version" $files
	unset IFS
done

chmod 0644 "$tmp"
mv "$tmp" "$out"
trap - EXIT
