#!/bin/sh
# Print the version for the current checkout.
#
# This is the single source of truth for the Makefile, the Publish workflow,
# and local Docker builds. The scheme is:
#
#   release tag vX.Y.Z      -> X.Y.Z
#   commits after a tag     -> X.Y.Z-<n>-<short-sha>
#   no tags                 -> 0.0.0-<n>-<short-sha>
#
# The leading "v" and the "g" emitted by git describe are stripped.
set -eu

if describe=$(git describe --tags --match 'v*' --abbrev=7 2>/dev/null) && [ -n "$describe" ]; then
	version=${describe#v}
	printf '%s\n' "$version" | sed 's/-g/-/'
	exit 0
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	count=$(git rev-list --count HEAD)
	sha=$(git rev-parse --short=7 HEAD)
	printf '0.0.0-%s-%s\n' "$count" "$sha"
	exit 0
fi

# Source tree without git metadata: fall back to the Semrel-maintained file.
if [ -f VERSION ]; then
	version=$(tr -d '[:space:]' < VERSION)
	if [ -n "$version" ]; then
		printf '%s\n' "$version"
		exit 0
	fi
fi

echo "version.sh: cannot determine a version: no git checkout and no VERSION file" >&2
exit 1
