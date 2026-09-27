#!/bin/bash
# matchvtables.py with MSVC's overload rule: what it changes, and whether it
# reproduces the slots read by hand.
cd derived || exit 0
echo "=== matchvtables.log"
cat matchvtables.log
echo "=== matchfuncs vtable pairs"
grep -E '^vtable pairs|string vs vtable' matchfuncs.log
# The matcher as main has it, on the same dumps, so the comparison below is
# the rule and nothing else.
mkdir -p /tmp/oldmv && curl -sSfL -o /tmp/oldmv/matchfuncs.py https://raw.githubusercontent.com/m-this/sigsegv-mvm-win/d94007d/tools/winport/matchfuncs.py
curl -sSfL -o /tmp/oldmv/matchvtables.py https://raw.githubusercontent.com/m-this/sigsegv-mvm-win/d94007d/tools/winport/matchvtables.py
(cd /tmp/oldmv && python3 matchvtables.py "$OLDPWD/linux-vtables" "$OLDPWD/win-vtables" "$OLDPWD/classified.json" > /dev/null) && cp /tmp/oldmv/winport_knownvtidx.txt old_knownvtidx.txt

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

committed, old, new = (entries(p) for p in ("../tools/winport/knownvtidx.generated.txt", "old_knownvtidx.txt", "winport_knownvtidx.txt"))
print(f"=== the old matcher against the committed file: {sum(1 for k in set(old) | set(committed) if old.get(k, (0,))[:3] != committed.get(k, (0,))[:3])} differ")
print(f"=== knownvtidx: old matcher {len(old)}, new {len(new)}")
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

print("=== vtable pairs against string matches, old rule and new")
sys.path.insert(0, "/tmp/oldmv")
addr = {}
for line in subprocess.run(["nm", "--defined-only", "../game-linux/tf/bin/server_srv.so"], capture_output=True, text=True).stdout.splitlines():
    p = line.split()
    if len(p) == 3:
        addr.setdefault(p[2], int(p[0], 16))
matches = json.load(open("matches.json"))
strings = {addr[k]: v["rva"] + 0x10000000 for k, v in matches.items() if v.get("via") == "string" and k in addr}
import importlib.util
for label, path in (("old", "/tmp/oldmv/matchfuncs.py"), ("new", "../tools/winport/matchfuncs.py")):
    spec = importlib.util.spec_from_file_location("mf_" + label, path)
    mf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mf)
    vt = mf.vtable_pairs("linux-vtables", "win-vtables")
    agree = sum(1 for l, w in vt.items() if strings.get(l) == w)
    disagree = sum(1 for l, w in vt.items() if l in strings and strings[l] != w)
    print(f"  {label}: {len(vt)} pairs, {agree} agree with a string match, {disagree} disagree")

print("=== why a base does not match")
for cls, base in (("CBasePlayer", "CBaseCombatCharacter"), ("CBaseCombatCharacter", "CBaseFlex"), ("CBaseCombatWeapon", "CEconEntity"),
                  ("CTFWeaponBase", "CBaseCombatWeapon"), ("CBaseEntity", "IServerEntity"), ("CGameMovement", "IGameMovement"),
                  ("CTFPlayer", "CBaseMultiplayerPlayer"), ("CBaseMultiplayerPlayer", "CBasePlayer"), ("CTFBotDead", "Action_CTFBot_")):
    if cls not in corpus.keys or base not in corpus.keys:
        print(f"  {cls} / {base}: no dump for {'both' if cls not in corpus.keys and base not in corpus.keys else cls if cls not in corpus.keys else base}")
        continue
    a, b = corpus.keys[cls], corpus.keys[base]
    bad = [(i, b[i], a[i]) for i in range(min(len(a), len(b))) if a[i] is not None and b[i] is not None and a[i] != b[i]]
    print(f"  {cls}({len(a)}) / {base}({len(b)}): parent {corpus.parent(cls)}, {len(bad)} mismatches, first {bad[:3]}")

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
print("ambiguous:", corpus.ambiguous)
PY

echo "=== side by side"
for q in "CBaseEntity 20 45" "CBaseEntity 140 152" "CBasePlayer 270 282" "CBasePlayer 448 458" "CGameMovement 0 24" "CTFGameMovement 8 14"; do
  python3 ../tools/winport/bed/side.py $q
done

echo "=== windows.txt with the new knownvtidx (and matchfuncs), against the committed one"
ver=$(grep -i '^ServerVersion=' ../game-windows/tf/steam.inf | cut -d= -f2 | tr -d '\r')
python3 ../tools/winport/emitgamedata.py matches.json "$ver" datamaps.json winport_knownvtidx.txt > windows.new.txt 2>/dev/null
diff -u ../gamedata/sigsegv/windows.txt windows.new.txt
true
