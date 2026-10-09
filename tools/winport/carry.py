#!/usr/bin/env python3
"""Move overrides.json from the build it holds for to the build served now.

    carry.py OLD_DIR NEW_DIR OLD_BUILD NEW_BUILD

OLD_DIR and NEW_DIR are game trees holding the libraries in LIBS.
Every entry whose build is OLD_BUILD goes through rebase.py against its own
library. One that carries gets the new rva and build and says so in `carried`;
one that does not keeps its old build, so emitgamedata.py leaves it out, and is
listed on stderr to be read by hand. overrides.json is rewritten in place.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import rebase  # noqa: E402

LIBS = {
    "server": "tf/bin/server.dll",
    "engine": "bin/engine.dll",
    "dedicated": "bin/dedicated.dll",
    "soundemittersystem": "bin/SoundEmitterSystem.dll",
}


def unmoved(old_path, new_path, rva, reason):
    """The same RVA, when the function's bytes did not change at all.

    rebase.py needs a body unique in the old build, and a template instance
    can share its body with another. When the update left the function where
    it was, byte for byte up to the next function, there is nothing to find."""
    old, new = rebase.Image(old_path), rebase.Image(new_path)
    va = rva + old.w.base
    if new.w.base != old.w.base or not old.w.in_text(va):
        return None, reason
    end = old.body_end(va)
    if new.body_end(va) != end:
        return None, reason
    a = old.w.text_bytes[va - old.w.text_start:end - old.w.text_start]
    b = new.w.text_bytes[va - new.w.text_start:end - new.w.text_start]
    if a != b:
        return None, reason
    return rva, f"{reason}, but unmoved: the same {len(a)} bytes at the same address"


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    old_dir, new_dir, old_build, new_build = sys.argv[1:5]
    path = Path(__file__).parent / "overrides.json"
    overrides = json.load(open(path))

    by_lib = {}
    for sym, entry in overrides.items():
        if entry.get("build") == old_build and "rva" in entry:
            by_lib.setdefault(entry.get("lib", "server"), []).append(sym)

    left = []
    for lib, syms in sorted(by_lib.items()):
        rel = LIBS[lib]
        if not Path(f"{old_dir}/{rel}").exists():
            # A kept build from before this library was kept.
            left += [f"{sym} {overrides[sym]['rva']} ({lib}): {rel} was not kept for {old_build}" for sym in syms]
            continue
        rvas = [int(overrides[s]["rva"], 16) for s in syms]
        out, why = rebase.rebase(f"{old_dir}/{rel}", f"{new_dir}/{rel}", rvas)
        for sym, rva in zip(syms, rvas):
            got = out[rva]
            if got is None:
                got, why[rva] = unmoved(f"{old_dir}/{rel}", f"{new_dir}/{rel}", rva, why[rva])
            if got is None:
                left.append(f"{sym} {rva:#x} ({lib}): {why[rva]}")
                continue
            entry = overrides[sym]
            entry["rva"] = f"{got:#x}"
            entry["build"] = new_build
            entry["carried"] = f"from {old_build} {rva:#x} by tools/winport/carry.py: {Path(rel).name}, {why[rva]}"

    path.write_text(json.dumps(overrides, indent=1) + "\n")
    total = sum(len(s) for s in by_lib.values())
    print(f"carried {total - len(left)} of {total} overrides from {old_build} to {new_build}", file=sys.stderr)
    for line in left:
        print("not carried: " + line, file=sys.stderr)


if __name__ == "__main__":
    main()
