#!/usr/bin/env bash
# Count how much of this extension already compiles for Windows.
#
# Nothing here has ever been built with an MSVC-compatible compiler, so "how
# much work is the Windows port" has only ever been a guess. This answers it as
# a number: run clang-cl over every source with the real include paths and
# defines, syntax only, and see which ones come back clean.
#
# It needs a Windows SDK and CRT, which xwin fetches from Microsoft's own CDN:
#
#     cargo install xwin
#     xwin --accept-license --arch x86 splat --output ~/xwin-sdk
#
# and the usual AlliedModders checkout next door, as the Linux CI lays it out:
# ambuild, sourcemod 1.11-dev, metamod-source 1.11-dev, hl2sdk tf2.
set -uo pipefail

XWIN="${XWIN:-$HOME/xwin-sdk}"
# Boost, header-only as this tree uses it: string algorithms, tokenizer, pool.
# The Linux build takes it from the system. Here it comes out of the Debian
# package without installing it:
#     apt-get download libboost1.83-dev && dpkg -x libboost1.83-dev_*.deb ~/winport-deps/boost
BOOST="${BOOST:-$HOME/winport-deps/boost/usr/include}"
AM="${ALLIEDMODDERS:-$(cd "$(dirname "$0")/../../.." && pwd)/alliedmodders}"
SDK="$AM/hl2sdk-tf2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
JOBS="${JOBS:-$(nproc)}"
OUT="${OUT:-/tmp/winport-census}"

for path in "$XWIN/crt/include" "$SDK/public" "$AM/sourcemod/public" "$AM/metamod-source/core"; do
	[ -d "$path" ] || { echo "missing: $path" >&2; exit 1; }
done
command -v clang-cl >/dev/null || { echo "clang-cl not on PATH" >&2; exit 1; }

# Windows does not care about the case of a header name and Linux does, and
# Microsoft's own headers are not consistent with themselves. Derived, so it is
# rebuilt here rather than committed.
# Built once, below, by the parent: a --one child rebuilding it would empty the
# directory under the children still reading it.
SHIM="${SHIM:-$OUT/caseshim}"

# SOURCE_ENGINE=12 and TF_DLL come from hl2sdk-manifests/manifests/tf2.json;
# COMPILER_MSVC32 and the CRT quieting come from AMBuildScript's configure_msvc.
# The engine defines AMBuildScript:578 gives every build: SE_<NAME>=<code> for
# every SDK manifest, which the tree compares SOURCE_ENGINE against, and
# SE_IS_<NAME> for the one being built. Without SE_IS_TF2 every TF2-specific
# stub is behind a false #ifdef, and CEconEntity, CMultiPlayerAnimState and the
# rest turn up as hundreds of unknown types. Derived from the manifests so a new
# SDK needs nothing here.
SE_DEFINES=$(python3 - "$AM/hl2sdk-manifests/manifests" <<'PY'
import json, pathlib, sys
for f in sorted(pathlib.Path(sys.argv[1]).glob("*.json")):
    d = json.loads(f.read_text())
    if "define" in d and "code" in d:
        print(f"/DSE_{d['define']}={d['code']}")
PY
)
# shellcheck disable=SC2206 # one flag per line, split on purpose
SE_DEFINES=($SE_DEFINES /DSE_IS_TF2)

FLAGS=(
	--target=i686-pc-windows-msvc /nologo /std:c++20 /EHsc /GR- /TP -fsyntax-only /W0
	/FI"$ROOT/tools/winport/msvc_prelude.h"
	# The Linux build force-includes the mod's own precompiled header into every
	# source, AMBuilder:546, and almost nothing here names it: src/util/buf.h
	# calls DevMsg with no include chain that could have declared it. Leaving
	# this out measured a tree that was never meant to compile without it.
	/FI"$ROOT/src/common.h"
	/I"$ROOT/tools/winport/shim" /I"$SHIM"
	/imsvc "$XWIN/crt/include" /imsvc "$XWIN/sdk/include/ucrt"
	/imsvc "$XWIN/sdk/include/um" /imsvc "$XWIN/sdk/include/shared"
	/I"$SDK/public" /I"$SDK/public/engine" /I"$SDK/public/mathlib" /I"$SDK/public/vstdlib"
	/I"$SDK/public/tier0" /I"$SDK/public/tier1" /I"$SDK/public/toolframework"
	/I"$SDK/public/game/server" /I"$SDK/game/shared" /I"$SDK/common"
	/I"$AM/sourcemod/public" /I"$AM/sourcemod/public/extensions"
	/I"$AM/sourcemod/public/amtl" /I"$AM/sourcemod/public/amtl/amtl"
	/I"$AM/sourcemod/sourcepawn/include"
	/I"$AM/metamod-source/core" /I"$AM/metamod-source/core/sourcehook"
	/I"$ROOT" /I"$ROOT/src" /I"$ROOT/src/sdk" /I"$ROOT/libs/udis86"
	/I"$ROOT/libs/fmt/include" /I"$ROOT/libs/lua/src"
	/imsvc "$BOOST"
	"${SE_DEFINES[@]}"
	/DSOURCE_ENGINE=12 /DGAME_DLL /DRAD_TELEMETRY_DISABLED
	/DCOMPILER_MSVC /DCOMPILER_MSVC32 /DWIN32 /D_WINDOWS /DTF_DLL
	/D_CRT_SECURE_NO_DEPRECATE /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_DEPRECATE
	/D_ITERATOR_DEBUG_LEVEL=0 /DHAVE_STDINT_H /DHAVE_STRING_H
	/DFMT_HEADER_ONLY /DVERSION_SAFE_STEAM_API_INTERFACES
)

compile_one() {
	local file="$1"
	local log="$OUT/errors/$(echo "$file" | tr '/' '_').log"
	if clang-cl "${FLAGS[@]}" "$file" > "$log" 2>&1; then
		rm -f "$log"; echo "ok $file"
	else
		echo "fail $file"
	fi
}

# xargs cannot call a shell function, so each file re-enters this script. That
# has to happen before the setup below, or the worker wipes the run it is part of.
if [ "${1:-}" = "--one" ]; then cd "$ROOT"; compile_one "$2"; exit 0; fi

rm -rf "$OUT"; mkdir -p "$OUT/errors"
bash "$(dirname "$0")/caseshim.sh" "$SHIM" \
	"$XWIN/sdk/include/um" "$XWIN/sdk/include/shared" \
	"$XWIN/sdk/include/ucrt" "$XWIN/crt/include"
cd "$ROOT"
# The sources AMBuilder builds by default, not every .cpp under src: a third of
# those are mods it lists commented out, which nobody compiles on Linux either.
python3 - <<'PY' > "$OUT/sources"
import types
text = open("AMBuilder").read()
ext = types.SimpleNamespace(name="sigsegv", exclude=[], optimize_mods_only=False)
scope = {"Extension": ext}
exec(text[:text.index("project = builder.LibraryProject")], scope)
print("\n".join(sorted(set(scope["sourceFiles"]))))
PY
echo "$(wc -l < "$OUT/sources") sources, $JOBS jobs"

xargs -a "$OUT/sources" -P "$JOBS" -I{} "$0" --one {} > "$OUT/results"

ok=$(grep -c '^ok ' "$OUT/results")
fail=$(grep -c '^fail ' "$OUT/results")
echo
echo "compiles clean : $ok"
echo "fails          : $fail"
echo
echo "top error kinds:"
cat "$OUT"/errors/*.log 2>/dev/null \
	| grep -oE "error: [^[]*" | sed 's/error: //' \
	| sed -E "s/'[^']*'/'X'/g; s/[0-9]+/N/g" \
	| sort | uniq -c | sort -rn | head -15
