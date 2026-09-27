#!/bin/bash
# The dreadwood fault (server.dll+0x38a36c under +0x380434, called from Squirrel),
# SetFOV, the CTFSword speed and health mods, and the most called unresolved.
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

# PE helpers: any address in the image, and every place its VA is written
secs = [(s.VirtualAddress, s.get_data(), s.Name.rstrip(b"\0").decode()) for s in pe.sections]
def wbytes(rva, n):
    for va, d, _ in secs:
        if va <= rva < va + len(d): return d[rva-va:rva-va+n]
    return b""
def wstr(rva):
    b = wbytes(rva, 80)
    e = b.find(b"\0")
    if e > 2 and all(32 <= c < 127 for c in b[:e]): return repr(b[:e].decode())
def wrefs(rva):
    needle = (base + rva).to_bytes(4, "little"); out = []
    for va, d, name in secs:
        at = d.find(needle)
        while at != -1:
            out.append((name, va + at)); at = d.find(needle, at + 1)
    return out
def wdis2(start, limit=250):
    print(f"== windows {start:#x}  ({len(wg.get(start, ()))} direct callers)")
    for n, i in enumerate(md.disasm(code[start-tv:start-tv+8000], base + start)):
        line = f"  {i.address-base:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16) - base; line += f"    -> {t:#x}"
            if t in kname: line += " " + kname[t]
        for m in re.finditer(r"0x[0-9a-f]{8}", i.op_str):
            v = int(m.group(0), 16) - base
            s = wstr(v) if 0 < v < 0x2000000 else None
            if s: line += "    str " + s
            elif v in kname: line += "    = " + kname[v]
        print(line)
        if i.mnemonic == "int3" or n >= limit: break
def wwho(rva):
    f = wstart(rva)
    print(f"#### {rva:#x} is in {f:#x}" + (" " + kname[f] if f in kname else ""))
    print("  callers: " + ", ".join(sorted({hex(wstart(s)) + (' ' + kname[wstart(s)] if wstart(s) in kname else '') for s in wg.get(f, ())})[:20]))
    for sec, at in wrefs(f)[:12]:
        print(f"  VA written in {sec} at {at:#x}")
        if sec == ".text":
            s = at - 40
            for i in md.disasm(code[s-tv:s-tv+90], base + s):
                line = f"     {i.address-base:#x}  {i.mnemonic} {i.op_str}"
                for m in re.finditer(r"0x[0-9a-f]{8}", i.op_str):
                    st = wstr(int(m.group(0), 16) - base)
                    if st: line += "    str " + st
                print(line)
        else:
            row = []
            for k in range(-8, 12):
                v = int.from_bytes(wbytes(at + 4*k, 4), "little") - base
                row.append(f"{4*k:+d}:{v:#x}" + (" " + (wstr(v) or kname.get(v, "")) if 0 < v < 0x2000000 else ""))
            print("     " + " | ".join(row))
    wdis2(f, 300)
    return f

print("######## dreadwood")
f1 = wwho(0x38a36c)
f2 = wwho(0x380434)

print("######## SetFOV")
ldis("_ZN11CBasePlayer6SetFOVEP11CBaseEntityifi", 400)
wdis2(0x20e3a0, 200)
for n in sorted(byname):
    if "CanOverrideEnvZoomOwner" in n or n.startswith("_ZN11CBasePlayer6GetFOV") or n.startswith("_ZNK11CBasePlayer6GetFOV"):
        ldis(n, 80); print("   windows:", hex(known[n]) if n in known else "unknown")

print("######## sword")
for n in ("_ZN8CTFSword16GetSwordSpeedModEv", "_ZN8CTFSword17GetSwordHealthModEv"):
    study(n, show=2, callers_show=0)
for n in sorted(byname):
    if n.startswith("_ZN8CTFSword") or n.startswith("_ZNK8CTFSword"):
        print("  sword sym", n, hex(byname[n][0]), byname[n][1], "windows " + hex(known[n]) if n in known else "")
for c in ("_ZN9CTFPlayer29TeamFortress_CalculateMaxSpeedEb", "_ZN9CTFPlayer22GetMaxHealthForBuffingEv"):
    if c in byname:
        a, sz = byname[c]
        print(c, "linux", hex(a), "windows", hex(known[c]) if c in known else "unknown")

print("######## most called unresolved")
for pat in ("_ZN19CTFPointWeaponMimic4Fire", "_Z10TE_TFBlood", "_ZN14CTriggerCamera7Disable"):
    for n in sorted(byname):
        if n.startswith(pat):
            study(n, show=2, callers_show=2)
PY
