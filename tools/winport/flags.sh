# Compiler flags for a Windows build of this extension with clang-cl, shared by
# census.sh and build.sh. Sourced, not run. Expects ROOT, XWIN, AM, BOOST and
# SHIM set; sets SDK, SE_DEFINES, WIN_CFLAGS and WIN_CXXFLAGS.
#
# The flags follow AMBuildScript's MSVC branch. Where clang-cl needs something
# MSVC does not, the reason is next to it.

SDK="$AM/hl2sdk-tf2"
# build.sh points this at a patched copy, see there.
SOURCEHOOK="${SOURCEHOOK:-$AM/metamod-source/core/sourcehook}"

# The engine defines AMBuildScript gives every build: SE_<NAME>=<code> for
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

# Both languages. /arch:SSE2 is what MSVC assumes for x86 unasked; clang-cl
# targets a plain i686 and refuses the SDK's SSE intrinsics without it.
WIN_CFLAGS=(
	--target=i686-pc-windows-msvc /nologo /W0 /MT /arch:SSE2
	/imsvc "$XWIN/crt/include" /imsvc "$XWIN/sdk/include/ucrt"
	/imsvc "$XWIN/sdk/include/um" /imsvc "$XWIN/sdk/include/shared"
	/DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_DEPRECATE /D_CRT_SECURE_NO_WARNINGS
	/D_CRT_NONSTDC_NO_DEPRECATE /D_ITERATOR_DEBUG_LEVEL=0
)

WIN_CXXFLAGS=(
	"${WIN_CFLAGS[@]}" /std:c++20 /EHsc /GR- /TP
	# AMBuildScript's -Wno-narrowing and -Wno-deprecated-register, in clang's
	# spelling: both are errors in clang by default and only warnings in gcc.
	-Wno-c++11-narrowing -Wno-register
	/FI"$ROOT/tools/winport/msvc_prelude.h"
	# The Linux build force-includes the mod's own precompiled header into every
	# source, AMBuilder:546, and almost nothing here names it: src/util/buf.h
	# calls DevMsg with no include chain that could have declared it.
	/FI"$ROOT/src/common.h"
	/I"$ROOT/tools/winport/shim" /I"$SHIM"
	/I"$SDK/public" /I"$SDK/public/engine" /I"$SDK/public/mathlib" /I"$SDK/public/vstdlib"
	/I"$SDK/public/tier0" /I"$SDK/public/tier1" /I"$SDK/public/toolframework"
	/I"$SDK/public/game/server" /I"$SDK/game/shared" /I"$SDK/common"
	/I"$AM/sourcemod/public" /I"$AM/sourcemod/public/extensions"
	/I"$AM/sourcemod/public/amtl" /I"$AM/sourcemod/public/amtl/amtl"
	/I"$AM/sourcemod/sourcepawn/include"
	/I"$SOURCEHOOK" /I"$(dirname "$SOURCEHOOK")" /I"$AM/metamod-source/core"
	/I"$ROOT" /I"$ROOT/src" /I"$ROOT/src/sdk" /I"$ROOT/libs/udis86"
	/I"$ROOT/libs/fmt/include" /I"$ROOT/libs/lua/src" /I"$ROOT/libs/ann/include"
	/imsvc "$BOOST"
	"${SE_DEFINES[@]}"
	/DSOURCE_ENGINE=12 /DGAME_DLL /DRAD_TELEMETRY_DISABLED
	/DCOMPILER_MSVC /DCOMPILER_MSVC32 /DTF_DLL
	/DHAVE_STDINT_H /DHAVE_STRING_H
	/DFMT_HEADER_ONLY /DVERSION_SAFE_STEAM_API_INTERFACES
)
