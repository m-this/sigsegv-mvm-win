#!/usr/bin/env bash
# Symlinks for the Windows SDK headers this tree spells with a different case.
#
# Windows filesystems do not care about case and Linux ones do, so a source that
# says <Dbghelp.h> finds nothing next to the SDK's own DbgHelp.h. Microsoft's
# headers are not consistent with themselves either, so this is not one or two
# names.
#
# Rather than renaming anything in the SDK, which the next `xwin splat` would
# undo, or editing the includes, which is upstream's code, this builds a
# directory of symlinks and puts it first on the include path. It is derived,
# so it is generated rather than committed.
#
#     tools/winport/caseshim.sh OUTDIR SDKDIR [SDKDIR ...]
set -euo pipefail

out="${1:?usage: caseshim.sh OUTDIR SDKDIR [SDKDIR ...]}"
shift
root="$(cd "$(dirname "$0")/../.." && pwd)"

rm -rf "$out"
mkdir -p "$out"

# Every angle-bracket include in the tree, which is what resolves against the
# SDK. Quoted includes resolve next to their own file first and are the mod's.
wanted=$(grep -rhoE '#[[:space:]]*include[[:space:]]*<[A-Za-z0-9_.-]+>' "$root/src" \
	| sed -E 's/.*<([^>]+)>.*/\1/' | sort -u)

made=0
for name in $wanted; do
	found=""
	for dir in "$@"; do
		[ -e "$dir/$name" ] && { found="exact"; break; }
	done
	[ -n "$found" ] && continue

	# Same name in a different case, if the SDK has one.
	for dir in "$@"; do
		real=$(find "$dir" -maxdepth 1 -iname "$name" -print -quit 2>/dev/null || true)
		if [ -n "$real" ]; then
			ln -sf "$real" "$out/$name"
			made=$((made + 1))
			break
		fi
	done
done

echo "case shims: $made in $out"
