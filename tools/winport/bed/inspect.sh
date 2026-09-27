#!/bin/bash
# Round 3: where scopes are released on each side, the mimic's four Fire
# functions, the CTFSword mods and TE_TFBlood by body, ED_Alloc on Linux.
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


def fsize(f):
    n = 0
    for i in md.disasm(code[f-tv:f-tv+6000], base + f):
        if i.mnemonic == "int3": return i.address - base - f
    return 6000


def fsize(f):
    for i in md.disasm(code[f-tv:f-tv+20000], base + f):
        if i.mnemonic == "int3": return i.address - base - f
    return 20000

print("######## scopes")
for n in sorted(byname):
    if ("ScriptScope" in n and ("Term" in n or "D2" in n or "D1" in n)) or n in ("_ZN11CBaseEntity14UpdateOnRemoveEv", "_ZN6CWorldD2Ev", "_ZN17CGlobalEntityList5ClearEv", "_ZN11CBaseEntityD2Ev"):
        a, sz = byname[n]
        cs = sorted({byaddr[lholder(x)] for x in lg.get(a, ())})
        print(f"  {n} {a:#x} {sz} callers({len(cs)}): " + ", ".join(cs[:30]))
for n in ("_ZN11CBaseEntity14UpdateOnRemoveEv", "_ZN11CBaseEntityD2Ev", "_ZN6CWorldD2Ev"):
    if n in byname:
        a, sz = byname[n]
        print(f"== linux callees of {n}")
        for i in md.disasm(lcode[a-lva:a-lva+sz], a):
            if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x") and int(i.op_str, 16) in byaddr:
                print(f"   {i.address:#x} {byaddr[int(i.op_str, 16)]}")
            m = re.search(r"\[e[a-d]x ([+-]) (0x[0-9a-f]+)\]", i.op_str)
            if m:
                d = int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
                if got + d in objs: print(f"   {i.address:#x} {i.mnemonic} {i.op_str}  obj {objs[got + d]}")
print("windows callers of 0x1fe240:")
for s_ in sorted(wg.get(0x1fe240, ())):
    f = wstart(s_)
    print(f"  call at {s_:#x} in {f:#x}" + (" " + kname[f] if f in kname else "") + f" size {fsize(f):#x}")

print("######## mimic")
for n in ("_ZN19CTFPointWeaponMimic10FireRocketEv", "_ZN19CTFPointWeaponMimic11FireGrenadeEv", "_ZN19CTFPointWeaponMimic9FireArrowEv", "_ZN19CTFPointWeaponMimic17FireStickyGrenadeEv"):
    ldis(n, 45)
for f in (0x5e1740, 0x5e1950, 0x5e1c60, 0x5e1e60):
    wdis2(f, 70)

print("######## sword and blood by body")
starts2 = [tv + i for i in range(1, len(code)) if code[i-1] == 0xcc and code[i] != 0xcc and (tv + i) % 16 == 0]
create = known["_ZN15CBaseTempEntity6CreateER16IRecipientFilterf"]
for f in starts2:
    txt = []
    for i in md.disasm(code[f-tv:f-tv+0xd0], base + f):
        if i.mnemonic == "int3": break
        txt.append(f"{i.mnemonic} {i.op_str}")
    else:
        continue
    j = "\n".join(txt)
    four = re.search(r"(cmp|cmovl|cmovle|cmovg|cmovge) [^\n]*, 4$|mov e.x, 4$", j, re.M)
    if four and "fld1" in j and "cvtsi2ss" in j and "mulss" in j:
        print(f"-- speed candidate {f:#x}"); wdis2(f, 60)
    elif four and re.search(r"imul e.., e.., 0xf$|lea e.., \[e.. \+ e..\*2\]", j, re.M) and "call dword ptr [e" in j and len(txt) < 45:
        print(f"-- health candidate {f:#x}"); wdis2(f, 60)
    if f"{base + create:#x}" in j and "ebp + 0x18" in j and "ebp + 0x1c" not in j and len(txt) < 50:
        print(f"-- blood candidate {f:#x}"); wdis2(f, 60)

print("######## ED_Alloc, Linux engine")
try:
    eelf = ELFFile(open("game-linux/bin/engine_srv.so", "rb"))
    et = eelf.get_section_by_name(".text"); ecode = et.data(); eva = et["sh_addr"]
    st = eelf.get_section_by_name(".symtab") or eelf.get_section_by_name(".dynsym")
    for s in st.iter_symbols():
        if s.name in ("_Z8ED_Allocv", "_Z8ED_Alloci", "sv", "_ZL12g_FreeEdicts", "g_FreeEdicts") or "ED_Alloc" in s.name:
            print("  sym", s.name, hex(s["st_value"]), s["st_size"])
            if s["st_info"]["type"] == "STT_FUNC":
                a = s["st_value"]
                for i in md.disasm(ecode[a-eva:a-eva+s["st_size"]], a):
                    print(f"   {i.address:#x}  {i.mnemonic} {i.op_str}")
except Exception as e:
    print("engine:", e)
PY
