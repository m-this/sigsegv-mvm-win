#!/bin/bash
# DecrementMannVsMachineWaveClassCount by the Windows offsets of the wave class
# arrays it walks.
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

# DecrementMannVsMachineWaveClassCount: the Windows offsets of the wave class
# arrays, read off the send table's construction (the offset is pushed just
# before the name), then the functions reading the names and the flags 0x60
# past them
rdata = {s.Name.rstrip(b"\0"): s for s in pe.sections}
def cstr_va(text_):
    for sec in pe.sections:
        data = sec.get_data(); at = data.find(b"\0" + text_ + b"\0")
        if at != -1: return base + sec.VirtualAddress + at + 1
offs = {}
for name in (b"m_nMannVsMachineWaveClassCounts", b"m_iszMannVsMachineWaveClassNames", b"m_nMannVsMachineWaveClassFlags", b"m_iszMannVsMachineWaveClassNames2", b"m_bMannVsMachineWaveClassActive"):
    va = cstr_va(name)
    print(f"== {name.decode()} string at {va:#x}" if va else f"== {name.decode()} not found")
    if not va: continue
    for m in re.finditer(re.escape(va.to_bytes(4, "little")), code):
        s = tv + m.start(); f = wstart(s)
        ins = list(md.disasm(code[max(f, s-80)-tv:s-tv+24], base + max(f, s-80)))
        k = next((j for j, i in enumerate(ins) if i.address - base >= s - 1), len(ins))
        for i in ins[max(0, k-10):k+3]: print(f"  {i.address-base:#x}  {i.mnemonic} {i.op_str}")
        imms = [int(x, 16) for i in ins[max(0, k-10):k] for x in re.findall(r"0x[0-9a-f]+", i.op_str) if 0x800 <= int(x, 16) < 0x2000]
        print("  offsets pushed before it:", [hex(x) for x in imms])
        offs.setdefault(name.decode(), []).extend(imms)
for d in sorted(set(offs.get("m_iszMannVsMachineWaveClassNames", []))):
    funcs = collections.Counter(wstart(tv + m.start()) for m in re.finditer(re.escape(d.to_bytes(4, "little")), code))
    both = [f for f in funcs if (d + 0x60).to_bytes(4, "little") in code[f-tv:f-tv+4000] and (d + 0x30).to_bytes(4, "little") in code[f-tv:f-tv+4000]]
    print(f"== names at {d:#x}: {len(funcs)} functions use it; with +0x30 and +0x60 too: {[hex(f) for f in both]}")
    for f in both:
        print(f"  callers of {f:#x}: " + ", ".join(sorted({hex(wstart(s)) + (' ' + kname[wstart(s)] if wstart(s) in kname else '') for s in wg.get(f, ())})))
    for f in both: wdis(f, 450)
PY
