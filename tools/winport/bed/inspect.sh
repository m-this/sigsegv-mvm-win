#!/bin/bash
# matchvtables.py with MSVC's overload rule: what it changes, and whether it
# reproduces the slots read by hand.
cd derived || exit 0
echo "=== matchvtables.log"
cat matchvtables.log
echo "=== matchfuncs vtable pairs"
grep -E '^vtable pairs|string vs vtable' matchfuncs.log

python3 - <<'PY'
import json, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, "../tools/winport")
import matchvtables as mv

def entries(path):
    out = {}
    for m in re.finditer(r'"([^"]+)"\n\{\n\ttype +"func knownvtidx"\n\tvtable +"([^"]+)"\n\tidx +"(\d+)"\n\t// (\S+); linux \+0x([0-9a-f]+), windows (0x[0-9a-f]+)\n\t// ([^\n]*)', Path(path).read_text()):
        out[m.group(1)] = (m.group(2), int(m.group(3)), m.group(6), m.group(7))
    return out

old, new = entries("../tools/winport/knownvtidx.generated.txt"), entries("winport_knownvtidx.txt")
print(f"=== knownvtidx: committed {len(old)}, derived {len(new)}")
for name in sorted(set(old) | set(new)):
    o, n = old.get(name), new.get(name)
    if o is None or n is None or o[:3] != n[:3]:
        fmt = lambda e: f"{e[0]} idx {e[1]} {e[2]}" if e else "-"
        print(f"CHANGED {name}: {fmt(o)}  ->  {fmt(n)}   // {(n or o)[3]}")

print("=== ground truth: overrides.json vtidx")
corpus = mv.Corpus("linux-vtables")
over = json.load(open("../tools/winport/overrides.json"))
syms = [s for s, e in over.items() if "vtidx" in e and s.startswith("_Z")]
dem = subprocess.run(["c++filt"], input="\n".join(syms), capture_output=True, text=True).stdout.splitlines()
for sym, sig in zip(syms, dem):
    e = over[sym]
    cls = mv.split_name(sig)[0]
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", cls)
    if stem not in corpus.tables or not Path(f"win-vtables/{stem}.txt").exists():
        print(f"  {sym}: no dump for {cls}")
        continue
    linux = corpus.tables[stem]
    win = mv.read_windows(Path(f"win-vtables/{stem}.txt")).get(0) or []
    if sig not in linux:
        print(f"  {sym}: {sig} not in {cls}'s Linux table")
        continue
    got = []
    for label, order in (("old", None), ("new", corpus.order(stem))):
        arranged = [linux[i] for i in order] if order else list(linux)
        how, aligned = mv.align(linux, win, order)
        flat = aligned or mv.collapse_destructors(arranged)
        got.append((label, flat.index(sig), how or f"unaligned {len(flat)} vs {len(win)}"))
    want = int(e["vtidx"])
    verdict = "OK" if got[1][1] == want else "WRONG"
    print(f"  {verdict} {cls} {sig}: hand {want}, " + ", ".join(f"{l} {i} ({h})" for l, i, h in got))

print("=== parent chains of the classes wanted")
wanted = sorted({r["class"] for r in json.load(open("classified.json"))["virtual"]})
for cls in wanted:
    if cls not in corpus.tables:
        continue
    chain, c = [], cls
    while c:
        chain.append(f"{c}({len(corpus.tables[c])})")
        c = corpus.parent(c)
    print("  " + " < ".join(chain))
print("moved:", dict(corpus.moved))
PY

echo "=== windows.txt with the new knownvtidx, against the committed one"
ver=$(grep -i '^ServerVersion=' ../game-windows/tf/steam.inf | cut -d= -f2 | tr -d '\r')
python3 ../tools/winport/emitgamedata.py matches.json "$ver" datamaps.json winport_knownvtidx.txt > windows.new.txt 2>/dev/null
diff -u ../gamedata/sigsegv/windows.txt windows.new.txt
true
