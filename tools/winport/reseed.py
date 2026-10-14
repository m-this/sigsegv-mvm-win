#!/usr/bin/env python3
"""Run the call-graph propagation again with the verified addresses as seeds.

matchfuncs.py seeds phase 2 with the pairs its string phase found, and stops
when a round adds nothing. Every address since verified by hand or by
corroborate.py is a pair it did not have, and a pair is an anchor: between two
calls both sides agree on, a stretch with one unmatched call on each side names
that call. So adding them and running propagation again can reach functions the
first run could not.

    reseed.py server_srv.so server.dll matches.json overrides.json out.json

Writes the new pairs only, in the same shape as matches.json, with
"via": "reseed". They carry no more evidence than propagation ever does, so
score them before believing any of them.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import matchfuncs as mf  # noqa: E402


def main():
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    linux_path, windows_path, matches_path, overrides_path, out_path = sys.argv[1:6]
    linux = mf.Linux(linux_path)
    windows = mf.Windows(windows_path)
    matches = json.load(open(matches_path))
    overrides = json.load(open(overrides_path))

    seeds = {}
    for name, match in matches.items():
        address = linux.by_name.get(name)
        if address is not None:
            seeds[address] = match["rva"] + windows.base
    before = len(seeds)
    for symbol, entry in overrides.items():
        if entry.get("bad"):
            seeds.pop(linux.by_name.get(symbol, -1), None)
            continue
        address = linux.by_name.get(symbol)
        if address is not None:
            seeds[address] = int(entry["rva"], 16) + windows.base
    print(f"seeds: {before} from matches, {len(seeds)} with the overrides")

    added = mf.propagate(linux, windows, seeds)
    print(f"propagation added {len(added)} pairs")

    out = {}
    for address, value in added.items():
        windows_address = value[0] if isinstance(value, tuple) else value
        name = linux.functions.get(address, (None,))[0]
        if not name or name in matches:
            continue
        out[name] = {"rva": windows_address - windows.base, "via": "reseed", "evidence": []}
    json.dump(out, open(out_path, "w"), indent=1)
    print(f"wrote {len(out)} pairs that matches.json does not have to {out_path}")


if __name__ == "__main__":
    main()
