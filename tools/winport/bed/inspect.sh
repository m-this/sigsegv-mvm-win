#!/bin/bash
# Pop mismatches: PlayerSolidMask, CTFGameRules' constructor, the grenade's
# Destroy, IVision::IsAbleToSee and VScriptServerInit, each Windows body next
# to the Linux one; then every vtidx entry of windows.txt whose Linux name is
# overloaded in its class, with the slots around it on both sides.
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

print("######## PlayerSolidMask")
ldis("_ZN15CTFGameMovement15PlayerSolidMaskEb", 80)
ldis("_ZN12CGameMovement15PlayerSolidMaskEb", 40)
wbody(0x476370, 80, "windows.txt PlayerSolidMask")
print("callers of 0x476370:", " ".join(f"{c:#x}(in {fstart(c):#x})" for c in callers(0x476370)[:20]))
for idx, va, name in ltable("CTFGameMovement"):
    if "PlayerSolidMask" in name: print(f"  linux slot {idx} {name}")
side_by_side("CTFGameMovement", 0, 90)

print("######## CTFGameRules ctor")
ldis("_ZN12CTFGameRulesC1Ev", 90)
ldis("_ZN12CTFGameRulesC2Ev", 10)
wbody(0x47ad20, 90, "windows.txt CTFGameRules C1")
print("callers of 0x47ad20:", " ".join(f"{c:#x}(in {fstart(c):#x})" for c in callers(0x47ad20)[:20]))
vt = win_header("CTFGameRules")
print(f"CTFGameRules primary vtable {vt:#x}" if vt else "no CTFGameRules vtable header")
if vt:
    needle = vt.to_bytes(4, "little")
    for m in re.finditer(re.escape(needle), code):
        at = tv + m.start(); fs = fstart(at)
        print(f"  vtable written at {at:#x} in {fs:#x} ret {wpop(fs)}  {whead(fs, 8)}")
        print("    callers:", " ".join(f"{c:#x}(in {fstart(c):#x})" for c in callers(fs)[:10]))
for n, (a, s) in syms.items():
    if "CreateGameRulesObject" in n or "12CTFGameRulesC" in n: print(f"  linux {n} {a:#x} size {s}")

print("######## CTFWeaponBaseGrenadeProj::Destroy")
ldis("_ZN24CTFWeaponBaseGrenadeProj7DestroyEbb", 60)
wbody(0x6395c0, 60, "windows.txt Destroy")
for idx, va, name in ltable("CTFWeaponBaseGrenadeProj"):
    if "Destroy" in name: print(f"  linux slot {idx} {name}")
for idx, va, _ in wtable("CTFWeaponBaseGrenadeProj"):
    if 228 <= idx <= 238: print(f"  W[{idx}] {va-base:#x} ret {wpop(va-base)}  {whead(va-base)}")

print("######## IVision::IsAbleToSee")
ldis("_ZNK7IVision11IsAbleToSeeEP11CBaseEntityNS_20FieldOfViewCheckTypeEP6Vector", 90)
ldis("_ZNK7IVision11IsAbleToSeeERK6VectorNS_20FieldOfViewCheckTypeE", 90)
for cls in ("CDisableVision", "IVision", "CTFBotVision"):
    side_by_side(cls, 55, 68)
for idx, va, _ in wtable("CDisableVision"):
    if idx in (61, 62): wbody(va - base, 90, f"CDisableVision slot {idx}")

print("######## VScriptServerInit")
ldis("_Z17VScriptServerInitv", 160)
wbody(0x38a700, 160, "windows.txt VScriptServerInit")
print("callers of 0x38a700:", " ".join(f"{c:#x}(in {fstart(c):#x})" for c in callers(0x38a700)[:20]))
for n, (a, s) in syms.items():
    if "VScriptServer" in n: print(f"  linux {n} {a:#x} size {s}")

print("######## overload audit")
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
def bare(sig):
    depth = 0
    for i in range(len(sig) - 1, -1, -1):
        if sig[i] == ")": depth += 1
        elif sig[i] == "(":
            depth -= 1
            if depth == 0: return sig[:i].strip()
    return sig
def method(sig): return bare(sig).split("::")[-1]
print(f"{len(entries)} vtidx entries")
for e, d in zip(entries, dem):
    cls = known.get(e["name"], e["name"].split("::")[0])
    lt_ = ltable(cls)
    if not lt_:
        print(f"-- {e['name']}: no linux table for {cls}"); continue
    same = [(i, n) for i, _, n in lt_ if method(n) == method(d)]
    if len({n for _, n in same}) < 2: continue
    v = int(e["vtidx"])
    print(f"== {e['name']}  [{cls}]  {d}  vtidx {v}  addr {e.get('addr')}  ret {wpop(int(e['addr'], 16)) if 'addr' in e else '?'}")
    for i, n in same: print(f"   L[{i}] {n}")
    lo = min(i for i, _ in same)
    for i, va, n in lt_:
        if lo - 2 <= i <= max(i for i, _ in same) + 2 and (i, n) not in same: print(f"   L[{i}] {n}")
    for idx, va, _ in wtable(cls):
        if v - 4 <= idx <= v + 4:
            print(f"   W[{idx}] {va-base:#x} ret {wpop(va-base)}  {whead(va-base, 5)}")
PY
