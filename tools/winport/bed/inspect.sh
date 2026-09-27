#!/bin/bash
# Second round: the bodies that decide PlayerSolidMask, CTFGameRules'
# constructor, VScriptServerInit and the overloads the first round found, and
# every vtidx entry's pop against the arguments its symbol declares.
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

print("######## PlayerSolidMask slot 12")
wbody(0x475320, 60, "CTFGameMovement slot 12")
for idx, va, _ in wtable("CGameMovement"):
    if 9 <= idx <= 13: print(f"  CGameMovement W[{idx}] {va-base:#x} ret {wpop(va-base)}  {whead(va-base, 10)}")
for idx, va, name in ltable("CGameMovement"):
    if 5 <= idx <= 13 or 26 <= idx <= 29: print(f"  CGameMovement L[{idx}] {va:#x} {name}")

print("######## CTFGameRules by RTTI")
data = pe.get_memory_mapped_image()
def rva_of_bytes(b, start=0):
    return [m.start() for m in re.finditer(re.escape(b), data)]
for tdname in (b".?AVCTFGameRules@@",):
    for at in rva_of_bytes(tdname):
        td = base + at - 8
        print(f"type descriptor {td:#x}")
        for c in rva_of_bytes(td.to_bytes(4, "little")):
            col = c - 12
            sig, off, cd = (int.from_bytes(data[col+k:col+k+4], "little") for k in (0, 4, 8))
            if sig not in (0, 1): continue
            print(f"  COL at {col:#x} offset {off:#x}")
            for v in rva_of_bytes((base + col).to_bytes(4, "little")):
                vt = base + v + 4
                print(f"    vtable {vt:#x}")
                for m in re.finditer(re.escape(vt.to_bytes(4, "little")), code):
                    w = tv + m.start(); fs = fstart(w)
                    print(f"      written at {w:#x} in {fs:#x} ret {wpop(fs)}; callers " + " ".join(f"{x:#x}(in {fstart(x):#x})" for x in callers(fs)[:8]))
                    print("\n".join(wdis(fs, 40)))
print("linux callers of CTFGameRules C1:", " ".join(f"{c:#x}({lfunc_of(c)})" for c in lcallers(0xc641a0)))
a, z = syms["_ZN12CTFGameRulesC1Ev"]
print("linux C1 callees in order:")
seen = []
for i in md.disasm(lcode[a-lva:a-lva+z], a):
    if i.mnemonic == "call" and i.op_str.startswith("0x"):
        n = lname.get(int(i.op_str, 16), i.op_str)
        if n not in seen: seen.append(n)
print("  " + "\n  ".join(seen[:60]))

print("######## VScriptServerInit callers")
print("linux callers:", " ".join(f"{c:#x}({lfunc_of(c)})" for c in lcallers(syms["_Z17VScriptServerInitv"][0])))
for fs in (fstart(0x38a860),):
    print(f"windows function holding 0x38a860 starts {fs:#x} ret {wpop(fs)}; callers " + " ".join(f"{x:#x}(in {fstart(x):#x})" for x in callers(fs)))
    print("\n".join(wdis(fs, 70)))
for c in callers(fstart(0x38a860)):
    print(f"== caller {fstart(c):#x}")
    print("\n".join(wdis(fstart(c), 40)))
for c in lcallers(syms["_Z17VScriptServerInitv"][0])[:2]:
    ldis(lfunc_of(c), 40)

print("######## overload bodies")
for sym in ("_ZN11CBotNPCBody14AimHeadTowardsERK6VectorN5IBody18LookAtPriorityTypeEfP13INextBotReplyPKc",
            "_ZN11CBotNPCBody14AimHeadTowardsEP11CBaseEntityN5IBody18LookAtPriorityTypeEfP13INextBotReplyPKc"):
    ldis(sym, 45)
wbody(0x597ce0, 45, "CBotNPCBody W[50]")
wbody(0x597c70, 45, "CBotNPCBody W[51]")
for sym in ("_ZN11CBaseEntity8FVisibleEPS_iPS0_", "_ZN11CBaseEntity8FVisibleERK6VectoriPPS_"):
    ldis(sym, 60)
wbody(0x1f09f0, 60, "CBaseEntity W[148]")
wbody(0x1f0b20, 60, "CBaseEntity W[149]")
side_by_side("CBaseEntity", 28, 37)
for sym in ("_ZN11CBaseEntity8KeyValueEPKcS1_", "_ZN11CBaseEntity8KeyValueEPKcf", "_ZN11CBaseEntity8KeyValueEPKcRK6Vector", "_ZN9CGameText8KeyValueEPKcS1_"):
    ldis(sym, 30)
for r, l in ((0x201d30, "W[31]"), (0x201d90, "W[32]"), (0x2017c0, "windows.txt CBaseEntity::KeyValue"), (0x298dc0, "CGameText W[33]")):
    wbody(r, 30, l)
for sym in ("_ZN24CTFWeaponBaseGrenadeProj11InitGrenadeERK6VectorS2_P20CBaseCombatCharacterRK13CTFWeaponInfo",
            "_ZN24CTFWeaponBaseGrenadeProj11InitGrenadeERK6VectorS2_P20CBaseCombatCharacterif"):
    ldis(sym, 50)
wbody(0x63a140, 50, "W[245]")
wbody(0x63a170, 50, "W[244]")
side_by_side("CTFWeaponBaseGrenadeProj", 242, 248)
ldis("_ZN47CEconItemAttributeIterator_ApplyAttributeString23OnIterateAttributeValueEPK28CEconItemAttributeDefinitionRK17CAttribute_String", 30)
wbody(0x39e840, 30, "W[4]")
side_by_side("CDisableVision", 64, 69)
for idx, va, _ in wtable("CDisableVision"):
    if idx in (65, 66): wbody(va - base, 40, f"CDisableVision W[{idx}]")
for sym in ("_ZNK7IVision15IsInFieldOfViewERK6Vector", "_ZNK7IVision15IsInFieldOfViewEP11CBaseEntity"):
    ldis(sym, 40)

print("######## pop screen")
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
dem = subprocess.run(["c++filt"], input="\n".join(e["sym"] for e in entries), capture_output=True, text=True).stdout.splitlines()
def params(sig):
    depth, end = 0, None
    for i in range(len(sig) - 1, -1, -1):
        if sig[i] == ")":
            depth += 1
            if depth == 1: end = i
        elif sig[i] == "(":
            depth -= 1
            if depth == 0:
                inner = sig[i+1:end]; break
    else: return None
    out, d, cur = [], 0, ""
    for ch in inner:
        if ch in "<(": d += 1
        if ch in ">)": d -= 1
        if ch == "," and d == 0: out.append(cur.strip()); cur = ""
        else: cur += ch
    if cur.strip(): out.append(cur.strip())
    return out
SIZE = {"double": 8, "long long": 8, "unsigned long long": 8, "Vector": 12, "QAngle": 12, "AngularImpulse": 12, "Vector2D": 8}
def expect(sig):
    ps = params(sig)
    if ps is None: return None
    total = 0
    for p in ps:
        if p in ("void",): continue
        if p == "...": return None
        if p.endswith("*") or p.endswith("&") or p.endswith("const") and ("*" in p or "&" in p): total += 4
        elif p in SIZE: total += SIZE[p]
        else: total += 4
    return total
bad = 0
for e, d in zip(entries, dem):
    cls = known.get(e["name"], e["name"].split("::")[0])
    v = int(e["vtidx"]); want = expect(d)
    got = wpop(int(e["addr"], 16)) if "addr" in e else "?"
    at = next((va - base for i, va, _ in wtable(cls) if i == v), None)
    note = "" if at is None or "addr" not in e or at == int(e["addr"], 16) else f" (slot {v} of {cls} holds {at:#x})"
    if want is None or got in ("?",) or "/" in got: 
        print(f"?? {e['name']}  {d}  vtidx {v} ret {got}{note}"); continue
    if int(got) not in (want, want + 4):
        bad += 1
        print(f"!! {e['name']}  {d}  vtidx {v} [{cls}] ret {got}, arguments {want}{note}")
print(f"{bad} of {len(entries)} disagree")
PY
