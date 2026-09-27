#!/bin/bash
# Round 4: the sword mods as MSVC inlined them, CanDecapitate's slot, who
# deletes the game rules on each side, GetFiringAngles.
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


import struct, os
def lro(a, n=4):
    for sec in elf.iter_sections():
        va = sec["sh_addr"]
        if va and va <= a < va + sec["sh_size"] and sec["sh_type"] != "SHT_NOBITS":
            return sec.data()[a-va:a-va+n]
print("######## sword")
for a in (0x1317188, 0x11abbf8):
    b = lro(a); print(f"  linux {a:#x} = {struct.unpack('<f', b)[0] if b else None}")
hold = collections.Counter()
for m in re.finditer(rb"\x80[\x78-\x7f\xb8-\xbf]\x31\x08\x00\x00|\xc6[\x80-\x87]\x31\x08\x00\x00|\x0f\xb6[\x80-\xbf]\x31\x08\x00\x00", lcode):
    hold[byaddr[lholder(lva + m.start())]] += 1
print("  linux functions touching byte +0x831: " + ", ".join(f"{n}:{c}" for n, c in hold.most_common(40)))
def around4(f, n=0x4000):
    ins = list(md.disasm(code[f-tv:f-tv+n], base + f))
    for k, i in enumerate(ins):
        if i.mnemonic == "int3": ins = ins[:k]; break
    for k, i in enumerate(ins):
        if re.search(r", 4$", i.op_str) and i.mnemonic in ("cmp", "mov") and any(x.mnemonic in ("cvtsi2ss", "imul", "shl") for x in ins[k:k+8]):
            print(f"  -- at {i.address-base:#x}")
            for x in ins[max(0, k-45):k+14]:
                line = f"     {x.address-base:#x}  {x.mnemonic} {x.op_str}"
                if x.mnemonic == "call" and x.op_str.startswith("0x"):
                    t = int(x.op_str, 16) - base
                    if t in kname: line += "  " + kname[t]
                print(line)
for n in ("_ZN9CTFPlayer29TeamFortress_CalculateMaxSpeedEb", "_ZN9CTFPlayer22GetMaxHealthForBuffingEv"):
    print("==", n, hex(known[n]) if n in known else "unknown")
    if n in known: around4(known[n])
    if n in byname:
        a, sz = byname[n]
        ins = list(md.disasm(lcode[a-lva:a-lva+sz], a))
        for k, i in enumerate(ins):
            if "0x1f1c]" in i.op_str:
                print("   linux:")
                for x in ins[max(0, k-30):k+10]: print(f"     {x.address:#x}  {x.mnemonic} {x.op_str}")
                break
for cls in ("CTFSword", "CTFDecapitationMeleeWeaponBase"):
    for side in ("linux", "win"):
        path = f"derived/{side}-vtables/{cls}.txt"
        if os.path.exists(path):
            rows = open(path).read().splitlines()
            print(f"== {path}")
            for r in rows:
                m = re.match(r"\+0x([0-9a-f]+):", r)
                if m and 0x780 <= int(m.group(1), 16) <= 0x7c0: print("   " + r[:160])
for l in open("tools/winport/knownvtidx.generated.txt"):
    if "Decapitat" in l or "CTFSword" in l: print("  known:", l.rstrip()[:200])

print("######## game rules")
for n in ("_ZN6CWorldD2Ev",):
    ldis(n, 60)
needle = (0x17f63fc).to_bytes(4, "little")
at = lcode.find(needle); ws = set()
while at != -1:
    if lcode[at-1] == 0xa3 or lcode[at-2] in (0x89, 0xc7): ws.add(byaddr[lholder(lva + at)])
    at = lcode.find(needle, at + 1)
print("  linux writers of [0x17f63fc]: " + ", ".join(sorted(ws)))
for f in (0x27c1c0, 0x27c260, 0x27dff0, 0x34ea30, 0x39c460):
    print("  windows writer", hex(f), kname.get(f, ""), "callers:", ", ".join(sorted({hex(wstart(x)) + (" " + kname[wstart(x)] if wstart(x) in kname else "") for x in wg.get(f, ())})[:8]))
    wdis2(f, 45)

print("######## GetFiringAngles")
ldis("_ZNK19CTFPointWeaponMimic15GetFiringAnglesEv", 80)
wdis2(0x5e22b0, 90)
PY
