#!/usr/bin/env python3
"""Which address names the code uses have no Windows entry.

    namegaps.py [REPO] [--list]

Reads every name defined in gamedata/sigsegv (not windows.txt) and keeps those
that src/ spells as a string outside a comment. Each one lands in one bucket:

    table     gamedata/sigsegv/windows.txt has an entry for it
    runtime   found at run time on Windows: func knownvtidx on a .?AV table,
              func ebpprologue, func datamap, datamap, convar
    bad       tools/winport/overrides.json marks its symbol `bad`
    client    a "[client]" name, for a game client a dedicated server never runs
    missing   none of the above

--list prints the missing names grouped by class, then the `bad` ones, in the
form WINDOWS_COVERAGE.md uses.
"""

import collections
import glob
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import classify  # noqa: E402

args = [a for a in sys.argv[1:] if not a.startswith("--")]
root = Path(args[0] if args else Path(__file__).resolve().parents[2])

defined = {}
for path in sorted(glob.glob(str(root / "gamedata/sigsegv/*.txt"))):
    if path.endswith("windows.txt"):
        continue
    text = open(path).read()
    found = []
    classify.walk_addrs(classify.parse(text), found)
    for name, entry in found:
        if name and not (name.startswith("_Z") and not entry.get("sym")):
            if entry.get("sym") or name not in defined:
                defined[name] = entry
    # classify.py loses some addrs_group pairs; emitgamedata.py reads them the same way.
    common = {}
    for line in text.split("\n"):
        line = line.split("//")[0].strip()
        kv = re.match(r'^(type|lib)\s+"([^"]*)"$', line)
        if kv:
            common[kv.group(1)] = kv.group(2)
        pair = re.match(r'^"([^"]+)"\s+"([^"]+)"$', line)
        if pair and not pair.group(1).startswith("_Z") and not defined.get(pair.group(1), {}).get("sym"):
            defined[pair.group(1)] = {"type": common.get("type"), "sym": pair.group(2)}

source = []
for path in glob.glob(str(root / "src/**/*.cpp"), recursive=True) + glob.glob(str(root / "src/**/*.h"), recursive=True):
    text = open(path, errors="replace").read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    source.append(re.sub(r"(?m)^\s*//.*$", "", text))
quoted = set(re.findall(r'"([^"\n]+)"', "\n".join(source)))

table = set(re.findall(r'^\t\t\t\t"([^"]+)"\n', (root / "gamedata/sigsegv/windows.txt").read_text(), re.M))
overrides = json.load(open(root / "tools/winport/overrides.json"))
bad = {sym for sym, entry in overrides.items() if entry.get("bad")}

count = collections.Counter()
missing, recorded_bad = [], []
for name in sorted(n for n in defined if n in quoted):
    entry = defined[name]
    kind = entry.get("type") or ""
    if name in table:
        count["table"] += 1
    elif entry.get("sym") in bad:
        count["bad"] += 1
        recorded_bad.append(name)
    elif name.startswith("[client]"):
        count["client"] += 1
    elif kind.startswith(("func ebpprologue", "func datamap", "convar", "datamap")) \
            or (kind == "func knownvtidx" and entry.get("vtable", "").startswith(".?AV")):
        count["runtime"] += 1
    else:
        count["missing"] += 1
        missing.append(name)

print(f"{len(defined)} names defined in gamedata/sigsegv, {sum(count.values())} named in src/: "
      + ", ".join(f"{count[k]} {k}" for k in ("table", "runtime", "bad", "client", "missing")))

if "--list" in sys.argv:
    by_class = collections.defaultdict(list)
    for name in missing:
        cls, sep, member = name.partition("::")
        by_class[cls if sep else "(free functions)"].append(member if sep else name)
    for cls in sorted(by_class, key=lambda c: (c == "(free functions)", c)):
        members = ", ".join(f"`{m}`" for m in sorted(by_class[cls]))
        print(f"- `{cls}` ({len(by_class[cls])}): {members}")
    print(f"\nRecorded `bad` ({len(recorded_bad)}): " + ", ".join(f"`{n}`" for n in sorted(recorded_bad)) + ".")
