#!/usr/bin/env python3
"""Score a match on evidence it did not already have, so a weak one can earn its place.

emitgamedata.py refuses a structural match whose field-offset agreement is under
FIELDS_MIN, because two of those with none at all killed a server and took a
bisection to find. That refusal is right and it is also blunt: 316 of the
addresses that fail on Windows have a candidate sitting behind it.

This recomputes, for each one, the evidence the match record does not carry:

  strings   string literals the Linux function references that the Windows
            candidate references too, and how many each has that the other
            does not. A function alone in referencing a string is how
            matchfuncs.py makes its strongest matches in the first place.
  callees   of the Linux function's callees that were themselves matched, how
            many the Windows candidate also calls. A wrong candidate rarely
            calls the same set.
  size      the two function sizes. Far apart is a warning, not a verdict:
            MSVC and GCC do not emit the same number of bytes.

    corroborate.py server_srv.so server.dll matches.json graphs.pickle gated.json

Prints a row per address and a summary. It promotes nothing on its own: read
the rows, and put what you accept in overrides.json with its reason, which is
where an address that a person vouched for belongs.
"""

import json
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import matchfuncs as mf  # noqa: E402


def main():
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    linux = mf.Linux(sys.argv[1])
    windows = mf.Windows(sys.argv[2])
    matches = json.load(open(sys.argv[3]))
    linux_graph, windows_graph = pickle.load(open(sys.argv[4], "rb"))
    gated = json.load(open(sys.argv[5]))

    forward = {
        linux.by_name[name]: match["rva"] + windows.base
        for name, match in matches.items()
        if name in linux.by_name
    }
    linux_strings, windows_strings = {}, {}
    for text, functions in linux.string_references().items():
        for function in functions:
            linux_strings.setdefault(function, set()).add(text)
    for text, functions in windows.string_references().items():
        for function in functions:
            windows_strings.setdefault(function, set()).add(text)

    rows = []
    for name, symbol, via, fields, lib in gated:
        match = matches.get(symbol)
        address = linux.by_name.get(symbol)
        if match is None or address is None:
            continue
        candidate = match["rva"] + windows.base
        shared = linux_strings.get(address, set()) & windows_strings.get(candidate, set())
        only_linux = linux_strings.get(address, set()) - windows_strings.get(candidate, set())
        only_windows = windows_strings.get(candidate, set()) - linux_strings.get(address, set())
        wanted = [forward[t] for t in set(linux_graph.get(address, ())) if t in forward]
        called = set(windows_graph.get(candidate, ()))
        hit = sum(1 for t in wanted if t in called)
        rows.append({
            "name": name, "symbol": symbol, "via": via, "fields": fields, "lib": lib,
            "rva": match["rva"], "strings_shared": sorted(shared)[:4],
            "strings_only_linux": len(only_linux), "strings_only_windows": len(only_windows),
            "callees_hit": hit, "callees_matched": len(wanted),
        })

    rows.sort(key=lambda r: (-len(r["strings_shared"]),
                             -(r["callees_hit"] / r["callees_matched"] if r["callees_matched"] else 0)))
    strong = 0
    for row in rows:
        ratio = row["callees_hit"] / row["callees_matched"] if row["callees_matched"] else 0
        # A shared string is near conclusive; so is most of a callee set, when
        # the set is big enough for "most" to mean anything.
        good = bool(row["strings_shared"]) or (row["callees_matched"] >= 4 and ratio >= 0.75)
        strong += good
        mark = "STRONG" if good else "      "
        print(f'{mark} {row["name"][:52]:52} via={row["via"]:9} '
              f'strings={len(row["strings_shared"])} (+{row["strings_only_linux"]}/'
              f'+{row["strings_only_windows"]}) callees={row["callees_hit"]}/{row["callees_matched"]}')
        if row["strings_shared"]:
            print(f'         shared: {row["strings_shared"]}')
    print(f"\n{strong} of {len(rows)} carry evidence the gate did not see", file=sys.stderr)
    json.dump(rows, open("corroborated.json", "w"), indent=1)
    print("wrote corroborated.json", file=sys.stderr)


if __name__ == "__main__":
    main()
