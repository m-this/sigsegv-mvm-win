#!/bin/bash
# Rebuild hl2sdk's prebuilt tier1 archives from the SDK's own tier1 sources.
#
# hl2sdk-manifests links lib/public/linux*/tier1*.a, and AlliedModders does not
# always rebuild them when a TF2 update changes a tier1 struct. On 2026-10-02
# KeyValues gained a field; the headers had it and the archives did not, and
# the extension crashed at load reading KeyValues with the old layout.
set -euo pipefail

sdk=$(realpath "$1")
jobs=${JOBS:-$(nproc)}
sources=$(sed -n '/project.sources = \[/,/\]/p' "$sdk/tier1/AMBuilder" | grep -oE "'[^']+\.cpp'" | tr -d "'")
sources="$sources processor_detect_linux.cpp"

common=(-std=gnu++2a -fPIC -fvisibility=hidden -fvisibility-inlines-hidden -fno-strict-aliasing -w
	-DLINUX -D_LINUX -DPOSIX -D_FILE_OFFSET_BITS=64 -DCOMPILER_GCC -DGNUC -DHAVE_STDINT_H -DHAVE_STRING_H
	-DNO_HOOK_MALLOC -DNO_MALLOC_OVERRIDE -DSOURCE_ENGINE=12 -DGAME_DLL
	-I"$sdk/common" -I"$sdk/public" -I"$sdk/public/tier0" -I"$sdk/public/tier1")

build() {
	local archive=$1
	shift
	local objects
	objects=$(mktemp -d)
	printf '%s\n' $sources | xargs -P "$jobs" -I{} sh -c \
		'g++ "$@" -c "'"$sdk"'/tier1/{}" -o "'"$objects"'/$(basename {} .cpp).o"' _ "${common[@]}" "$@"
	rm -f "$archive"
	ar rcs "$archive" "$objects"/*.o
	echo "rebuilt $archive from $(ls "$objects" | wc -l) objects"
	rm -rf "$objects"
}

build "$sdk/lib/public/linux/tier1_i486.a" -m32 -march=core2 -msse2 -mfpmath=sse
build "$sdk/lib/public/linux64/tier1.a" -m64 -march=core2 -DX64BITS -DPLATFORM_64BITS
