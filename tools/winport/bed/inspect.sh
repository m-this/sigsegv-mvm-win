#!/bin/bash
# DispatchParticleEffect's overloads, CTraceFilterSimple's constructor,
# CopyStringAttributeValueToCharPointerOutput, DecrementMannVsMachineWaveClassCount
# and CollectBuiltObjects: the Linux bodies with their calls named, and the
# Windows functions calling the same known callees or called by the same
# known callers.
python3 - <<'PY'
import re, bisect, collections, capstone, pefile
from elftools.elf.elffile import ELFFile

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# Linux
elf = ELFFile(open("game-linux/tf/bin/server_srv.so", "rb"))
ltext = elf.get_section_by_name(".text")
lcode = ltext.data(); lva = ltext["sh_addr"]
got = elf.get_section_by_name(".got.plt")["sh_addr"]
ro = elf.get_section_by_name(".rodata"); rodata = ro.data(); rova = ro["sh_addr"]
byaddr, byname, objs = {}, {}, {}
for s in elf.get_section_by_name(".symtab").iter_symbols():
    if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
        byaddr.setdefault(s["st_value"], s.name); byname[s.name] = (s["st_value"], s["st_size"])
    elif s["st_info"]["type"] == "STT_OBJECT" and s["st_value"]:
        objs[s["st_value"]] = s.name
def lstr(a):
    if rova <= a < rova + len(rodata):
        o = a - rova; e = rodata.find(b"\0", o)
        return repr(rodata[o:e][:60].decode(errors="replace"))
lg = collections.defaultdict(set)
at = lcode.find(b"\xe8")
while at != -1:
    src = lva + at; dst = src + 5 + int.from_bytes(lcode[at+1:at+5], "little", signed=True)
    if dst in byaddr: lg[dst].add(src)
    at = lcode.find(b"\xe8", at + 1)
starts = sorted(byaddr)
def lholder(a):
    return starts[bisect.bisect_right(starts, a) - 1]
def ldis(name, limit=700):
    a, n = byname[name]
    print(f"== linux {name} at {a:#x} size {n}")
    callees = []
    for k, i in enumerate(md.disasm(lcode[a-lva:a-lva+n], a)):
        line = f"  {i.address:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t in byaddr: line += "    -> " + byaddr[t]; callees.append(byaddr[t])
        m = re.search(r"\[e[a-d]x \+ (0x[0-9a-f]+)\]|\[e[a-d]x - (0x[0-9a-f]+)\]", i.op_str)
        if m:
            d = int(m.group(1), 16) if m.group(1) else -int(m.group(2), 16)
            s = lstr(got + d)
            if s: line += "    str " + s
            elif got + d in objs: line += "    obj " + objs[got + d]
        if k < limit: print(line)
    callers = sorted({byaddr[lholder(s)] for s in lg.get(a, ())})
    print(f"  linux callers ({len(callers)}): " + ", ".join(callers[:40]))
    return callees, callers

# Windows
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
def wstart(rva):
    at = rva - tv
    while at > 0 and not (code[at-1] in (0xCC, 0x90) and code[at-2] in (0xCC, 0x90)): at -= 1
    return tv + at
wg = collections.defaultdict(set)
at = code.find(b"\xe8")
while at != -1:
    src = tv + at; dst = src + 5 + int.from_bytes(code[at+1:at+5], "little", signed=True)
    if tv <= dst < tv + len(code): wg[dst].add(src)
    at = code.find(b"\xe8", at + 1)
known, kname = {}, {}
for m in re.finditer(r'sym\s+"([^"]+)"\s*\n\s*addr\s+"(0x[0-9a-f]+)"', open("gamedata/sigsegv/windows.txt").read()):
    known[m.group(1)] = int(m.group(2), 16); kname.setdefault(int(m.group(2), 16), m.group(1))
def wcallees(start, limit=4000):
    out = []
    for i in md.disasm(code[start-tv:start-tv+limit], base + start):
        if i.mnemonic == "call" and i.op_str.startswith("0x"): out.append(int(i.op_str, 16) - base)
        if i.mnemonic == "int3": break
    return out
def wdis(start, limit=250):
    print(f"== windows {start:#x}  ({len(wg.get(start, ()))} direct callers)")
    for n, i in enumerate(md.disasm(code[start-tv:start-tv+6000], base + start)):
        line = f"  {i.address-base:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16) - base; line += f"    -> {t:#x}"
            if t in kname: line += " " + kname[t]
        print(line)
        if i.mnemonic == "int3" or n >= limit: break
def wfind(callees, callers):
    ks = [c for c in dict.fromkeys(callees) if c in known]
    print(f"  known callees on Windows: {[(c, hex(known[c])) for c in ks]}")
    cnt = collections.Counter()
    for c in ks:
        for f in {wstart(s) for s in wg.get(known[c], ())}: cnt[f] += 1
    print("  windows functions by known callees shared: " + ", ".join(f"{f:#x}:{n}" for f, n in cnt.most_common(12)))
    kc = [c for c in callers if c in known]
    cc = collections.Counter()
    for c in kc:
        for t in set(wcallees(known[c])): cc[t] += 1
    print(f"  known callers on Windows: {[(c, hex(known[c])) for c in kc]}")
    print("  callees of those: " + ", ".join(f"{f:#x}:{n}" + (" " + kname[f] if f in kname else "") for f, n in cc.most_common(25)))
    return cnt, cc, kc

def study(name, show=2, callers_show=0):
    if name not in byname:
        print("missing", name); return
    callees, callers = ldis(name)
    cnt, cc, kc = wfind(callees, callers)
    for f, _ in cnt.most_common(show): wdis(f)
    for f, _ in [x for x in cc.most_common(40) if x[0] not in kname][:callers_show]: wdis(f)
    return kc

# DispatchParticleEffect: every overload, so the ones known on Windows anchor the rest
for n in sorted(k for k in byname if k.startswith("_Z22DispatchParticleEffect")):
    study(n, show=1, callers_show=3)
wdis(0x30efd0, 60)

# CTraceFilterSimple
for n in sorted(k for k in byname if "18CTraceFilterSimple" in k):
    ldis(n, 80)
print("== CTraceFilterSimple tables")
for side in ("linux", "win"):
    try: print(open(f"derived/{side}-vtables/CTraceFilterSimple.txt").read()[:1500])
    except Exception as e: print(side, e)
vt = None
try:
    for l in open("derived/win-vtables/CTraceFilterSimple.txt"):
        m = re.match(r'//.*vtable.*?(0x[0-9a-f]+)', l)
        if m and vt is None: vt = int(m.group(1), 16); vt = vt if vt >= base else vt + base; break
except Exception: pass
print("windows CTraceFilterSimple vtable va:", hex(vt) if vt else None)
if "_ZN18CTraceFilterSimple15ShouldHitEntityEP13IHandleEntityi" in known:
    wdis(known["_ZN18CTraceFilterSimple15ShouldHitEntityEP13IHandleEntityi"], 80)
if vt:
    pat = vt.to_bytes(4, "little"); sites = []
    at = code.find(pat)
    while at != -1 and len(sites) < 400:
        sites.append(tv + at); at = code.find(pat, at + 1)
    print(f"  {len(sites)} code references to the vtable")
    funcs = sorted({wstart(s) for s in sites})
    print("  in functions: " + ", ".join(hex(f) for f in funcs[:60]))
    for s in sites[:6]:
        f = wstart(s)
        print(f"-- site {s:#x} in {f:#x}")
        ins = list(md.disasm(code[f-tv:s-tv+60], base + f))
        k = next((j for j, i in enumerate(ins) if i.address - base >= s - 8), 0)
        for i in ins[max(0, k-6):k+8]: print(f"  {i.address-base:#x}  {i.mnemonic} {i.op_str}")

# CopyStringAttributeValueToCharPointerOutput, and small Windows functions of
# its shape: an MSVC std::string's c_str is a compare of the capacity at +0x14
# with 16
study("_Z43CopyStringAttributeValueToCharPointerOutputPK17CAttribute_StringPPKc", show=2)
small = set()
for m in re.finditer(rb"\x83[\x78-\x7f]\x14\x10", code):
    f = wstart(tv + m.start())
    if tv + m.start() - f < 24: small.add(f)
print(f"== {len(small)} Windows functions comparing [r+0x14] with 16 in their first 24 bytes")
for f in sorted(small)[:25]:
    ins = []
    for i in md.disasm(code[f-tv:f-tv+64], base + f):
        ins.append(f"{i.mnemonic} {i.op_str}".strip())
        if i.mnemonic in ("ret", "int3") or len(ins) > 14: break
    print(f"  {f:#x} ({len(wg.get(f, ()))} callers): " + "; ".join(ins))
for n in ("_ZNK16CAttribute_String5valueEv", "_ZN16CAttribute_String9MergeFromERKS_"):
    if n in byname: ldis(n, 60)
for n in sorted(k for k in byname if "17CAttribute_String" in k)[:30]: print("  linux sym", n, byname[n])

# DecrementMannVsMachineWaveClassCount and its helpers
kc = study("_ZN20CTFObjectiveResource36DecrementMannVsMachineWaveClassCountE8string_tj", show=3, callers_show=3)
for n in sorted(k for k in byname if k.startswith("_ZN20CTFObjectiveResource")):
    print("  linux sym", n, byname[n])

# CollectBuiltObjects
study("_ZN10CTFNavMesh19CollectBuiltObjectsEP10CUtlVectorIP11CBaseObject10CUtlMemoryIS2_iEEi", show=3, callers_show=3)
PY
