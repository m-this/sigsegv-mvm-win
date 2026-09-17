#!/usr/bin/env bash
# Build sigsegv.ext.2.tf2.dll for Windows from Linux, with clang-cl and lld-link.
#
# census.sh asks which sources compile; this compiles them for real, along with
# the libraries the Linux build links prebuilt out of libs/, and links the DLL.
# Needs what census.sh needs, see there.
#
#     OUT=/tmp/winport-build tools/winport/build.sh
#
# Objects are kept between runs. A source is recompiled when it, or a header it
# included last time, is newer than its object; a change of compiler flags or of
# the precompiled header recompiles everything that used them. OPT sets the
# optimisation, /O1 unless given: it compiles faster than /Ox and emits the same
# vcall thunk shapes, which /Od does not (the SourceHook patch reads them).
set -uo pipefail

XWIN="${XWIN:-$HOME/xwin-sdk}"
BOOST="${BOOST:-$HOME/winport-deps/boost/usr/include}"
AM="${ALLIEDMODDERS:-$(cd "$(dirname "$0")/../../.." && pwd)/alliedmodders}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
JOBS="${JOBS:-$(nproc)}"
OPT="${OPT:-/O1}"
OUT="${OUT:-/tmp/winport-build}"
SHIM="$OUT/caseshim"
# SourceHook finds a virtual function's slot by reading the compiler's vcall
# thunk and knows only MSVC's. clang-cl's loads the slot into a register first,
# so unpatched every SH_DECL_HOOK and GetFuncInfo sees a non-virtual function.
# Measured on CBaseNPC, where it ended the server at map start. The patch is
# applied to a copy so the shared metamod checkout stays as it is.
SOURCEHOOK="$OUT/metamod/core/sourcehook"

# shellcheck source=tools/winport/flags.sh
. "$ROOT/tools/winport/flags.sh"

obj_of() { echo "$OUT/obj/$(echo "$1" | sed -E 's|^/||; s|/|_|g').obj"; }

PCH="$OUT/pch.pch"

# True when obj is missing or older than its source, the precompiled header it
# was built with, or any header its dependency list names.
stale() {
	local obj="$1" file="$2"
	[ -f "$obj" ] && [ "$obj" -nt "$file" ] || return 0
	[ "$3" = ext ] && [ "$PCH" -nt "$obj" ] && return 0
	[ -f "$obj.deps" ] || return 0
	newer_than "$obj" "$obj.deps"
}

# True when any path listed in the file is newer than target, or has gone.
newer_than() {
	local deps
	mapfile -t deps < "$2"
	[ -n "$(find -L "${deps[@]}" -newer "$1" -print -quit 2>&1)" ]
}

# clang-cl writes Make syntax; one path per line is what stale() reads.
write_deps() {
	sed -e '1s/^[^:]*://' -e 's/\\$//' "$1" | tr -s ' \t' '\n' | sed '/^$/d' > "$2"
	rm -f "$1"
}

# One source to one object, logging to $OUT/errors when it fails. Re-entered
# through xargs, which cannot call a shell function.
compile_one() {
	local kind="$1" file="$2" obj log
	obj=$(obj_of "$file")
	log="$OUT/errors/$(basename "$obj" .obj).log"
	stale "$obj" "$file" "$kind" || { echo "ok $file"; return; }
	local flags
	case "$kind" in
	# /Z7 so a crash under winedbg names a function rather than an offset.
	ext) flags=("${WIN_CXXFLAGS[@]}" "$OPT" /Oy- /Z7 /I"$OUT/gen" /Yu"$ROOT/tools/winport/pch.h" /Fp"$PCH") ;;
	# ANN is written as a DLL; built into this one, its exports are harmless and
	# the dllimport its header gives callers resolves locally at link time.
	ann) flags=("${WIN_CFLAGS[@]}" /TP /EHsc "$OPT" /DDLL_EXPORTS /I"$ROOT/libs/ann/include" /I"$ROOT/libs/ann/src") ;;
	# As C++, the way CI builds liblua.a (make CC=g++): the extension includes
	# the Lua headers without extern "C", and Lua raises errors as C++ exceptions
	# rather than longjmp. LUA_COMPAT_5_3 is from libs/lua/src/Makefile.
	lua) flags=("${WIN_CFLAGS[@]}" /TP /EHsc "$OPT" /DLUA_COMPAT_5_3) ;;
	udis86) flags=("${WIN_CFLAGS[@]}" /TC "$OPT" /DHAVE_STRING_H /I"$OUT/gen" /I"$ROOT/libs/udis86" /I"$ROOT/libs/udis86/libudis86") ;;
	# Built on its own, as AMBuilder's autoversion step builds it: version.h
	# forced in for the extern "C", none of the extension's headers.
	version) flags=("${WIN_CFLAGS[@]}" /TP /FI"$ROOT/src/version.h") ;;
	esac
	if clang-cl "${flags[@]}" /clang:-MMD /clang:-MF"$obj.d" -c "$file" /Fo"$obj" > "$log" 2>&1; then
		write_deps "$obj.d" "$obj.deps"
		rm -f "$log"; echo "ok $file"
	else
		rm -f "$obj" "$obj.d" "$obj.deps"; echo "fail $file"
	fi
}

if [ "${1:-}" = "--one" ]; then cd "$ROOT"; compile_one "$2" "$3"; exit 0; fi

rm -rf "$OUT/errors"
mkdir -p "$OUT/obj" "$OUT/errors" "$OUT/gen"
if [ ! -d "$SOURCEHOOK" ]; then
	mkdir -p "$OUT/metamod/core"
	cp -r "$AM/metamod-source/core/sourcehook" "$OUT/metamod/core/"
	patch -s -d "$OUT/metamod" -p1 < "$ROOT/tools/winport/patches/sourcehook-clang-cl-vcall-thunks.patch" || exit 1
fi
# Rebuilt beside the old one and swapped in only when it differs, so unchanged
# symlinks keep their times and do not make every object look stale.
bash "$ROOT/tools/winport/caseshim.sh" "$SHIM.new" \
	"$XWIN/sdk/include/um" "$XWIN/sdk/include/shared" \
	"$XWIN/sdk/include/ucrt" "$XWIN/crt/include"
if diff -r --no-dereference "$SHIM.new" "$SHIM" > /dev/null 2>&1; then
	rm -rf "$SHIM.new"
else
	rm -rf "$SHIM"; mv "$SHIM.new" "$SHIM"
fi
cd "$ROOT"

# Different flags make different objects: start over when they change.
flags_id=$(printf '%s\n' "${WIN_CFLAGS[@]}" "${WIN_CXXFLAGS[@]}" "$OPT" | sha256sum | cut -c1-16)
if [ "$(cat "$OUT/flags.id" 2>/dev/null)" != "$flags_id" ]; then
	rm -f "$OUT"/obj/* "$PCH" "$PCH.deps"
	echo "$flags_id" > "$OUT/flags.id"
fi

# The precompiled header, before any source that uses it.
pch_stale() {
	[ -f "$PCH" ] && [ -f "$PCH.deps" ] || return 0
	newer_than "$PCH" "$PCH.deps"
}
if pch_stale; then
	echo "precompiling pch.h"
	printf '#include "%s"\n' "$ROOT/tools/winport/pch.h" > "$OUT/pch.cpp"
	clang-cl "${WIN_CXXFLAGS[@]}" "$OPT" /Oy- /Z7 /I"$OUT/gen" /Yc"$ROOT/tools/winport/pch.h" /Fp"$PCH" \
		/clang:-MMD /clang:-MF"$PCH.d" -c "$OUT/pch.cpp" /Fo"$OUT/pch.obj" > "$OUT/errors/pch.log" 2>&1 \
		|| { cat "$OUT/errors/pch.log"; exit 1; }
	write_deps "$PCH.d" "$PCH.deps"
fi

# udis86 generates its opcode tables; the Linux build links a libudis86.a that
# was built with them.
[ -f "$OUT/gen/itab.c" ] || python3 libs/udis86/scripts/ud_itab.py \
	libs/udis86/docs/x86/optable.xml "$OUT/gen" > /dev/null

{
	python3 - <<'PY'
import types
text = open("AMBuilder").read()
# The groups configure.py can already leave out, left out: they are tools for
# working on the mod rather than for running missions, and debug and visualize
# carry code that was only ever built for Linux, and in one case for a 2017
# Windows client.
ext = types.SimpleNamespace(name="sigsegv", exclude=["mods_debug", "mods_visualize", "mods_vgui"], optimize_mods_only=False)
scope = {"Extension": ext}
exec(text[:text.index("project = builder.LibraryProject")], scope)
# Sources that are Linux by design rather than by accident, each with why.
linux_only = {
    # Watches the workshop map folder with inotify.
    "src/mod/etc/workshop_map_fix.cpp",
}
for f in sorted(set(scope["sourceFiles"]) - linux_only):
    print("ext", f)
PY
	# AMBuilder takes src/sdk/smsdk_ext.cpp over SourceMod's when it exists.
	if [ -f src/sdk/smsdk_ext.cpp ]; then echo "ext src/sdk/smsdk_ext.cpp"
	else echo "ext $AM/sourcemod/public/smsdk_ext.cpp"; fi
	echo "version src/version.cpp"
	for f in libs/ann/src/*.cpp; do echo "ann $f"; done
	for f in libs/lua/src/*.c; do
		case "$f" in */lua.c|*/luac.c) ;; *) echo "lua $f" ;; esac
	done
	for f in libs/udis86/libudis86/*.c "$OUT/gen/itab.c"; do echo "udis86 $f"; done
} > "$OUT/sources"

echo "$(wc -l < "$OUT/sources") sources, $JOBS jobs"
self="$ROOT/tools/winport/build.sh"
tr '\n' '\0' < "$OUT/sources" | xargs -0 -P "$JOBS" -I{} sh -c '"$0" --one $1' "$self" {} > "$OUT/results"

ok=$(grep -c '^ok ' "$OUT/results")
failed=$(grep -c '^fail ' "$OUT/results")
echo "compiled: $ok, failed: $failed"
[ "$failed" -eq 0 ] || { grep '^fail ' "$OUT/results" | head -20; exit 1; }

echo "linking"
mapfile -t objects < <(sed -E 's/^[a-z0-9]+ //' "$OUT/sources" | while read -r f; do obj_of "$f"; done)
objects+=("$OUT/pch.obj")
lld-link /nologo /DLL /MACHINE:X86 /DEBUG /errorlimit:0 /OUT:"$OUT/sigsegv.ext.2.tf2.dll" \
	/LIBPATH:"$XWIN/crt/lib/x86" /LIBPATH:"$XWIN/sdk/lib/um/x86" /LIBPATH:"$XWIN/sdk/lib/ucrt/x86" \
	"${objects[@]}" \
	"$SDK/lib/public/x86/tier0.lib" "$SDK/lib/public/x86/tier1.lib" \
	"$SDK/lib/public/x86/vstdlib.lib" "$SDK/lib/public/x86/mathlib.lib" \
	legacy_stdio_definitions.lib kernel32.lib user32.lib gdi32.lib advapi32.lib \
	shell32.lib ole32.lib oleaut32.lib uuid.lib ws2_32.lib dbghelp.lib psapi.lib \
	> "$OUT/link.log" 2>&1
status=$?
grep -c 'error' "$OUT/link.log" | sed 's/^/link errors: /'
[ "$status" -eq 0 ] && echo "built $OUT/sigsegv.ext.2.tf2.dll"
exit "$status"
