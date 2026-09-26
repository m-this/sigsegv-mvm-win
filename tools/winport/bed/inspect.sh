#!/bin/bash
# CAttribute_String's layout on Windows, the Windows functions walking the
# objective resource's wave class arrays, and CollectBuiltObjects among the
# callees of CTFBotMedicHeal::Update.
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

# CAttribute_String: where value_ lives, read off the Windows virtuals and
# GetCustomProjectileModel, against Linux
print(open("derived/linux-vtables/CAttribute_String.txt").read()[:3000])
wrows = [int(m.group(1), 16) for m in re.finditer(r"^\+0x[0-9a-f]+:\s+([0-9a-f]+)", open("derived/win-vtables/CAttribute_String.txt").read(), re.M)]
for n, va in enumerate(wrows[:24]):
    print(f"-- windows slot {n}"); wdis(va - base, 45)
for n in ("_ZN17CAttribute_String5ClearEv", "_ZN17CAttribute_String9MergeFromERKS_", "_ZN17CAttribute_String4SwapEPS_", "_ZN16CTFWeaponBaseGun24GetCustomProjectileModelEP17CAttribute_String"):
    ldis(n, 90)
wdis(known["_ZN16CTFWeaponBaseGun24GetCustomProjectileModelEP17CAttribute_String"], 120)

# The wave class arrays: cmp name, [obj + i*4 + D], then and flags, [obj + i*4 + D + 0x60]
print("== windows functions walking a string_t[12] and the flags 0x60 past it")
hits = collections.defaultdict(set)
for m in re.finditer(rb"[\x39\x3b][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x80-\xbf]", code):
    at = m.start(); d = int.from_bytes(code[at+3:at+7], "little")
    if not 0x800 <= d < 0x2000: continue
    if (d + 0x60).to_bytes(4, "little") in code[at+7:at+48]:
        hits[wstart(tv + at)].add(d)
for f in sorted(hits):
    print(f"  {f:#x} names at {sorted(hex(d) for d in hits[f])}, {len(wg.get(f, ()))} callers, called from " + ", ".join(sorted({hex(wstart(s)) + (' ' + kname[wstart(s)] if wstart(s) in kname else '') for s in wg.get(f, ())})[:12]))
for f in sorted(hits): wdis(f, 160)
for n in ("_ZN20CTFObjectiveResource31SetMannVsMachineWaveClassActiveE8string_tb", "_ZN20CTFObjectiveResource36IncrementMannVsMachineWaveClassCountE8string_tj"):
    if n in byname: ldis(n, 60)
for n in ("_ZN11CTFTankBoss14UpdateOnRemoveEv", "_ZN20CTFObjectiveResource24DecrementTeleporterCountEv", "_ZN9CTFPlayer12Event_KilledERK15CTakeDamageInfo"):
    print(n, hex(known[n]) if n in known else "not known on Windows", [hex(f) for f in hits if n in known and f in set(wcallees(known[n], 30000))])

# CollectBuiltObjects: a callee of CTFBotMedicHeal::Update comparing the team
# with -2 (TEAM_ANY) and popping 8
for f in sorted(set(wcallees(known["_ZN15CTFBotMedicHeal6UpdateEP6CTFBotf"], 20000))):
    if not tv <= f < tv + len(code): continue
    txt = []
    for i in md.disasm(code[f-tv:f-tv+1500], base + f):
        txt.append(f"{i.mnemonic} {i.op_str}".strip())
        if i.mnemonic == "int3": break
    if any(", -2" in t for t in txt) and "ret 8" in txt:
        wdis(f, 160)
# Who calls the CTraceFilterSimple constructor and DispatchParticleEffect [overload 3]
for f in (0x36ea30, 0x2a9a10):
    hs = sorted({wstart(s) for s in wg.get(f, ())})
    print(f"== {f:#x}: {len(wg.get(f, ()))} calls from {len(hs)} functions; known: " + ", ".join(kname[h] for h in hs if h in kname))
PY
