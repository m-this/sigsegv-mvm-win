#!/bin/bash
# Attribute list, provider, DispatchTraceAttack and weapon virtual bodies, Windows against Linux.
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


rdata = [(s.VirtualAddress, s.get_data()) for s in pe.sections if s.Name.rstrip(b"\0") in (b".rdata", b".data")]
def wstr(s):
    out = []
    for va, data in rdata:
        for m in re.finditer(re.escape(b"\0" + s.encode() + b"\0"), data):
            out.append(va + m.start() + 1)
    return out
def wrefs(s):
    fs = set()
    for a in wstr(s):
        pat = (base + a).to_bytes(4, "little")
        at = code.find(pat)
        while at != -1:
            fs.add(wstart(tv + at)); at = code.find(pat, at + 1)
    print(f"  windows functions referencing {s!r}: " + ", ".join(f"{f:#x}" for f in sorted(fs)))
    return sorted(fs)
def wrows(cls):
    out = []
    for l in open(f"derived/win-vtables/{cls}.txt"):
        if l.startswith("// vtable") and "offset 0x0" not in l and out: break
        m = re.match(r"\s*\+0x([0-9a-f]+):\s+([0-9a-f]+)", l)
        if m: out.append(int(m.group(2), 16) - base)
    return out
def lrows(cls):
    out = []
    for l in open(f"derived/linux-vtables/{cls}.txt"):
        if l.startswith("// vtable") and "offset 0x0000" not in l and out: break
        m = re.match(r"\s*\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)", l)
        if m: out.append(m.group(3).strip())
    return out
def wpop(start):
    pops = set()
    for i in md.disasm(code[start-tv:start-tv+0x3000], base + start):
        if i.mnemonic == "int3": break
        if i.mnemonic == "ret": pops.add(int(i.op_str, 16) if i.op_str else 0)
    return sorted(pops)
def whead(start, n=7):
    return "; ".join(f"{i.mnemonic} {i.op_str}" for i in list(md.disasm(code[start-tv:start-tv+0x60], base + start))[:n])
def slots(cls, fn, lo=10, hi=10):
    lin, win = lrows(cls), wrows(cls)
    hit = [k for k, n in enumerate(lin) if f"::{fn}(" in n]
    print(f"== {cls}: linux {len(lin)} slots, windows {len(win)}; {fn} at linux {hit}")
    if not hit: return
    t = hit[0]
    for k in range(t - lo, t + hi):
        if 0 <= k < len(lin): print(f"  L[{k}] {lin[k]}")
    for k in range(t - lo - 12, t + hi):
        if 0 <= k < len(win): print(f"  W[{k}] {win[k]:#x} ret {wpop(win[k])}  {whead(win[k])}")


def funcs_calling(target):
    return sorted({wstart(s) for s in wg.get(target, ())})
def fsize(f):
    n = 0
    for i in md.disasm(code[f-tv:f-tv+0x2000], base + f):
        if i.mnemonic == "int3": break
        n = i.address - base - f + i.size
    return n
def text_of(f, limit=0x400):
    out = []
    for i in md.disasm(code[f-tv:f-tv+limit], base + f):
        if i.mnemonic == "int3": break
        out.append(f"{i.mnemonic} {i.op_str}")
    return "\n".join(out)

print("\n######## provider")
for f in (0x39e6b0, 0x39e8b0, 0x39ea40): wdis(f, 120); print("  callers:", [hex(x) for x in funcs_calling(f)])

print("\n######## AddAttribute candidates")
both = set(funcs_calling(0x3b8810)) & set(funcs_calling(0x3b8e30))
for f in sorted(both):
    t = text_of(f)
    if fsize(f) < 260 and "+ 0x34]" in t:
        print(f"  cand {f:#x} size {fsize(f)} ret {wpop(f)}"); wdis(f, 80)

print("\n######## DestroyAllAttributes candidates")
at = 0
seen = set()
pat = re.compile(r"mov dword ptr \[e.x \+ 0x10\], 0")
for va, _ in [(tv, None)]:
    pass
cnt = 0
for f in sorted({wstart(s) for s in range(tv, tv + len(code), 1) if False}):
    pass
# scan every function that makes a vcall at +0x34 through the list's manager field (+0x18)
hits = []
off = 0
blob = code
i = blob.find(b"\xff\x50\x34")
while i != -1:
    hits.append(wstart(tv + i)); i = blob.find(b"\xff\x50\x34", i + 1)
for f in sorted(set(hits)):
    if f in seen: continue
    seen.add(f)
    t = text_of(f, 0x300)
    if fsize(f) < 200 and pat.search(t) and "+ 0x18]" in t:
        print(f"  cand {f:#x} size {fsize(f)} ret {wpop(f)} callers {len(wg.get(f,()))}"); wdis(f, 70)

print("\n######## DispatchTraceAttack candidates")
hits = set()
for pat2 in (b"\xff\x90\xf4\x00\x00\x00", b"\xff\x92\xf4\x00\x00\x00", b"\xff\x50\x00"):
    pass
i = code.find(b"\xf4\x00\x00\x00")
while i != -1:
    f = wstart(tv + i)
    if f not in hits and fsize(f) < 120:
        t = text_of(f, 0x100)
        if re.search(r"call dword ptr \[e.x \+ 0xf4\]", t) and re.search(r"\+ 0xf8\]", t) and 0x10 in wpop(f):
            hits.add(f); print(f"  cand {f:#x} size {fsize(f)} ret {wpop(f)} callers {len(wg.get(f,()))}"); wdis(f, 50)
    hits.add(f)
    i = code.find(b"\xf4\x00\x00\x00", i + 1)
wdis(0x60b170, 400)

print("\n######## SMG / pistol GetDamageType")
wdis(0x629750, 60)
wdis(0x624220, 400)
for a in (0x12da0cc, 0x12f03e3): print(hex(a), lstr(a))

def wstrat(rva):
    for va, data in rdata:
        if va <= rva < va + len(data):
            e = data.find(b"\0", rva - va); return data[rva-va:e][:60]
for a in (0x10860e00, 0x1087b3cc, 0x108f6148, 0x1087f870, 0x108e4ee4): print(hex(a), wstrat(a - base))

print("\n######## weapon virtuals")
for sym in ("_ZNK13CTFWeaponBase17AutoFiresFullClipEv", "_ZN13CTFWeaponBase13ItemBusyFrameEv", "_ZN13CTFWeaponBase16ItemHolsterFrameEv",
            "_ZNK13CTFWeaponBase16GetPenetrateTypeEv", "_ZN13CTFWeaponBase15GetSpreadAnglesEv"):
    ldis(sym, 90)
w = wrows("CTFWeaponBase")
for k in (273, 274, 275, 276, 285, 402, 403, 404, 405, 406):
    print(f"-- W[{k}]"); wdis(w[k], 70)
wdis(0x632e30, 90)
PY
