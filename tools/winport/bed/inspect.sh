#!/bin/bash
# Third round: CGameMovement's Accelerate and AirAccelerate against the slots
# its grouped GetPlayerMins/Maxs overloads displace, and every vtidx entry that
# sits between two non-adjacent overloads of its class on Linux.
python3 - <<'PY'
import re, subprocess, capstone, pefile
from pathlib import Path
from elftools.elf.elffile import ELFFile
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress

def wins(rva, size=0x3000):
    return md.disasm(code[rva-tv:rva-tv+size], base + rva)
def wdis(rva, n=60):
    out = []
    for i in wins(rva):
        out.append(f"    {i.address-base:#x}  {i.mnemonic} {i.op_str}")
        if i.mnemonic == "int3" or len(out) >= n: break
    return out
def wpop(rva):
    first = next(wins(rva, 16), None)
    if first is not None and first.mnemonic == "jmp" and first.op_str.startswith("0x"):
        rva = int(first.op_str, 16) - base
    pops = set()
    for k, i in enumerate(wins(rva, 0x4000)):
        if i.mnemonic == "int3": break
        if i.mnemonic == "ret": pops.add(int(i.op_str, 16) if i.op_str else 0)
    return "/".join(str(p) for p in sorted(pops)) or "?"
def whead(rva, n=6):
    return "; ".join(x.split("  ", 1)[1] for x in wdis(rva, n))
def fstart(rva):
    at = rva - tv
    while at > 0 and not (code[at-1] in (0xCC, 0x90) and code[at-2] in (0xCC, 0x90)): at -= 1
    return tv + at
def callers(rva):
    out = []
    for m in re.finditer(rb"\xe8", code):
        at = m.start()
        if at + 5 > len(code): break
        rel = int.from_bytes(code[at+1:at+5], "little", signed=True)
        if tv + at + 5 + rel == rva: out.append(tv + at)
    return out
def rows(path, first_only=True):
    out = []
    for l in open(path):
        m = re.match(r"\s*\+(0x[0-9a-f]+):\s+(0x[0-9a-f]+|[0-9a-f]+)\s*(.*)", l)
        if m: out.append((int(m.group(1), 16) // 4, int(m.group(2), 16), m.group(3).strip()))
        elif out and first_only and l.startswith("//"): break
    return out
def wtable(cls):
    p = Path(f"derived/win-vtables/{cls}.txt")
    return rows(p) if p.exists() else []
def ltable(cls):
    p = Path(f"derived/linux-vtables/{cls}.txt")
    return rows(p) if p.exists() else []
def win_header(cls):
    for l in open(f"derived/win-vtables/{cls}.txt"):
        m = re.match(r"// vtable at (0x[0-9a-fA-F]+) offset 0x0\b", l.strip())
        if m: return int(m.group(1), 16)

elf = ELFFile(open("game-linux/tf/bin/server_srv.so", "rb"))
lt = elf.get_section_by_name(".text"); lcode = lt.data(); lva = lt["sh_addr"]
syms = {s.name: (s["st_value"], s["st_size"]) for s in elf.get_section_by_name(".symtab").iter_symbols() if s["st_info"]["type"] == "STT_FUNC"}
lname = {}
for n, (a, s) in syms.items(): lname.setdefault(a, n)
def ldis(name, n=120):
    if name not in syms: print(f"== linux {name} absent"); return
    a, size = syms[name]
    print(f"== linux {name} at {a:#x} size {size}")
    for k, i in enumerate(md.disasm(lcode[a-lva:a-lva+size], a)):
        if k >= n: print("    ..."); break
        extra = ""
        if i.mnemonic == "call" and i.op_str.startswith("0x"):
            t = int(i.op_str, 16); extra = "  ; " + lname.get(t, "")
        print(f"    {i.address:#x}  {i.mnemonic} {i.op_str}{extra}")
def wbody(rva, n=120, label=""):
    print(f"== windows {rva:#x} {label} ret {wpop(rva)}")
    print("\n".join(wdis(rva, n)))
def side_by_side(cls, lo, hi, wcls=None):
    wcls = wcls or cls
    print(f"== {cls} linux slots {lo}..{hi}")
    for idx, va, name in ltable(cls):
        if lo <= idx <= hi: print(f"  L[{idx}] {va:#x} {name}")
    print(f"== {wcls} windows slots {lo-2}..{hi}")
    for idx, va, _ in wtable(wcls):
        if lo - 2 <= idx <= hi:
            rva = va - base
            print(f"  W[{idx}] {rva:#x} ret {wpop(rva)}  {whead(rva)}")

def lcallers(target):
    out = []
    for m in re.finditer(rb"\xe8", lcode):
        at = m.start()
        if at + 5 > len(lcode): break
        rel = int.from_bytes(lcode[at+1:at+5], "little", signed=True)
        if lva + at + 5 + rel == target: out.append(lva + at)
    return out
def lfunc_of(a):
    best = None
    for n, (s, z) in syms.items():
        if s <= a < s + z and (best is None or s > syms[best][0]): best = n
    return best

print("######## CGameMovement")
for idx, va, name in ltable("CGameMovement"):
    if idx <= 30: print(f"  L[{idx}] {va:#x} {name}")
for idx, va, _ in wtable("CGameMovement"):
    if idx <= 30: print(f"  W[{idx}] {va-base:#x} ret {wpop(va-base)}  {whead(va-base, 8)}")
ldis("_ZN13CGameMovement10AccelerateER6Vectorff", 45)
ldis("_ZN13CGameMovement13AirAccelerateER6Vectorff", 45)
for idx, va, _ in wtable("CGameMovement"):
    if idx in (16, 18, 20, 22): wbody(va - base, 45, f"CGameMovement W[{idx}]")

print("######## displaced zones")
known = {}
cur = None
for l in open("tools/winport/knownvtidx.generated.txt"):
    m = re.match(r'^"(.*)"$', l.strip())
    if m: cur = m.group(1)
    m = re.match(r'\s*vtable\s+"(.*)"', l)
    if m and cur: known[cur] = m.group(1)
entries, cur = [], None
for l in open("gamedata/sigsegv/windows.txt"):
    s = l.strip()
    m = re.match(r'^"(.*)"$', s)
    if m: cur = {"name": m.group(1)}; continue
    m = re.match(r'^(sym|addr|vtidx)\s+"(.*)"', s)
    if m and cur is not None: cur[m.group(1)] = m.group(2)
    if s == "}" and cur is not None:
        if "vtidx" in cur and "sym" in cur: entries.append(cur)
        cur = None
dem = dict(zip((e["sym"] for e in entries), subprocess.run(["c++filt"], input="\n".join(e["sym"] for e in entries), capture_output=True, text=True).stdout.splitlines()))
def bare(sig):
    depth = 0
    for i in range(len(sig) - 1, -1, -1):
        if sig[i] == ")": depth += 1
        elif sig[i] == "(":
            depth -= 1
            if depth == 0: return sig[:i].strip()
    return sig
def method(sig): return bare(sig).split("::")[-1]
zones = {}
for cls in sorted({known.get(e["name"], e["name"].split("::")[0]) for e in entries}):
    lt_ = ltable(cls)
    by = {}
    for i, _, n in lt_:
        if method(n).startswith("~"): continue
        by.setdefault(method(n), []).append(i)
    z = [(m, ix) for m, ix in by.items() if len(ix) > 1 and max(ix) - min(ix) >= len(ix)]
    if z: zones[cls] = z
for cls, z in zones.items():
    print(f"== {cls}: non-adjacent overloads " + "; ".join(f"{m} at {ix}" for m, ix in z))
for e in entries:
    cls = known.get(e["name"], e["name"].split("::")[0])
    if cls not in zones: continue
    d = dem.get(e["sym"], e["sym"])
    li = next((i for i, _, n in ltable(cls) if n == d), None)
    hit = [m for m, ix in zones[cls] if li is not None and min(ix) <= li <= max(ix)]
    if not hit: continue
    v = int(e["vtidx"])
    print(f"-- {e['name']} [{cls}] linux {li} windows {v} addr {e.get('addr')} ({', '.join(hit)})")
    for idx, va, _ in wtable(cls):
        if v - 2 <= idx <= v + 2:
            print(f"     W[{idx}] {va-base:#x} ret {wpop(va-base)}  {whead(va-base, 5)}")
PY
