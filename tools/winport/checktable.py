#!/usr/bin/env python3
"""Check the committed Windows address table against the build it says it holds for.

    checktable.py [REPO]

Every entry in gamedata/sigsegv/windows.txt is a fixed RVA keyed to a
ServerVersion, `tools/winport/table.json` records which one, and the extension
refuses to load when the server reports another. Those three have to agree:
a table whose entries say one build while table.json says another either
refuses to load on the build it was made for, or carries the next update's
overrides from the wrong binaries.

Nothing here needs the game, a network or a compiler, so it runs in a second
on every push rather than in the seven minutes the Address table job takes.
A name registered twice (dupes.py) is a disagreement too. Exits non-zero and
names every one.
"""

import json
import re
import sys
from pathlib import Path

import dupes

HEADER = re.compile(r"// Addresses in server\.dll for ServerVersion (\d+),")


def read_table(path):
    """name -> {key: value} per entry, in file order, plus the header's build.

    windows.txt is written by emitgamedata.py alone, one key per line at a
    fixed indent, which is the only reason reading it by line is honest.
    """
    text = path.read_text()
    header = HEADER.search(text)
    entries, name, depth = [], None, 0
    for line in text.split("\n"):
        stripped = line.split("//")[0].strip()
        depth += stripped.count("{") - stripped.count("}")
        quoted = re.fullmatch(r'"(.*)"', stripped)
        if quoted is not None and depth == 4:
            name = quoted.group(1)
            entries.append((name, {}))
        elif name is not None and depth == 5:
            kv = re.fullmatch(r'(\w+)\s+"(.*)"', stripped)
            if kv is not None:
                entries[-1][1][kv.group(1)] = kv.group(2)
    return entries, (header and int(header.group(1))), depth


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2])
    bad = []

    table = json.loads((root / "tools/winport/table.json").read_text())
    for key in ("build", "manifest"):
        if not str(table.get(key, "")).isdigit():
            bad.append(f"table.json: {key} is {table.get(key)!r}, not a number")
    if bad:
        sys.exit("\n".join(bad))
    build = int(table["build"])

    entries, header, depth = read_table(root / "gamedata/sigsegv/windows.txt")
    if depth != 0:
        bad.append(f"windows.txt: {depth} braces left open, so the file is truncated")
    if not entries:
        bad.append("windows.txt: no entries")
    if header != build:
        bad.append(f"windows.txt: the header is for ServerVersion {header}, table.json for {build}")

    addrs = {}
    for name, kv in entries:
        where = f"windows.txt: {name!r}"
        if name == "":
            # A name SourceMod can never look up. The tokeniser in classify.py
            # loses the names after misc.txt's unterminated CEyeballBossIdle
            # symbol, and emitgamedata.py leaves those entries out.
            bad.append(f"{where}: an entry with no name")
        elif kv.get("type") == "fixed":
            missing = [k for k in ("sym", "addr", "build", "lib") if k not in kv]
            if missing:
                bad.append(f"{where}: fixed, without {', '.join(missing)}")
            elif int(kv["build"]) != build:
                bad.append(f"{where}: keyed to ServerVersion {kv['build']}, table.json says {build}")
            # The first entry under a name wins, so a name carrying two
            # addresses means one of them is dead and nothing says which.
            elif addrs.setdefault(name, kv["addr"]) != kv["addr"]:
                bad.append(f"{where}: two addresses, {addrs[name]} and {kv['addr']}")
        elif kv.get("type") == "sendtable":
            if "table" not in kv:
                bad.append(f"{where}: sendtable, without table")
        else:
            bad.append(f"{where}: type is {kv.get('type')!r}, not fixed or sendtable")

    overrides = json.loads((root / "tools/winport/overrides.json").read_text())
    stale = 0
    for sym, entry in overrides.items():
        if entry.get("bad"):
            continue
        if "rva" not in entry:
            bad.append(f"overrides.json: {sym}: neither an rva nor bad")
        elif "build" not in entry:
            bad.append(f"overrides.json: {sym}: an rva with no build")
        elif int(entry["build"]) > build:
            bad.append(f"overrides.json: {sym}: build {entry['build']} is newer than the table's {build};"
                       " carry.py ran without the table being derived and committed")
        elif int(entry["build"]) < build:
            stale += 1

    summary, repeated = dupes.report(root)
    bad += [f"registered twice: {line}" for line in repeated]

    if bad:
        sys.exit("\n".join(bad[:50] + ([f"... and {len(bad) - 50} more"] if len(bad) > 50 else [])))
    print(f"windows.txt: {len(entries)} entries, all for ServerVersion {build} (depot 232255 manifest {table['manifest']})")
    print("\n".join(summary))
    print(f"overrides.json: {sum(1 for e in overrides.values() if not e.get('bad'))} addresses, "
          f"{stale} left at an older build for carry.py to read by hand")


if __name__ == "__main__":
    main()
