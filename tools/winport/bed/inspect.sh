#!/bin/bash
# Burn, GetConditionDuration, PlaySpecificSequence, HasAmmo and
# RemoveCustomAttribute: the Linux bodies with their calls and strings named,
# and the Windows functions calling the same known callees.
python3 - <<'PY'
import re, collections, capstone, pefile
from elftools.elf.elffile import ELFFile

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# Linux
elf = ELFFile(open("game-linux/tf/bin/server_srv.so", "rb"))
ltext = elf.get_section_by_name(".text")
lcode = ltext.data(); lva = ltext["sh_addr"]
got = elf.get_section_by_name(".got.plt")["sh_addr"]
ro = elf.get_section_by_name(".rodata"); rodata = ro.data(); rova = ro["sh_addr"]
byaddr, byname = {}, {}
for s in elf.get_section_by_name(".symtab").iter_symbols():
    if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
        byaddr.setdefault(s["st_value"], s.name); byname[s.name] = (s["st_value"], s["st_size"])
def lstr(a):
    if rova <= a < rova + len(rodata):
        o = a - rova; e = rodata.find(b"\0", o)
        return repr(rodata[o:e][:60].decode(errors="replace"))
def lcalls():
    g = collections.defaultdict(set)
    at = lcode.find(b"\xe8")
    while at != -1:
        src = lva + at; dst = src + 5 + int.from_bytes(lcode[at+1:at+5], "little", signed=True)
        if dst in byaddr: g[dst].add(src)
        at = lcode.find(b"\xe8", at + 1)
    return g
lg = lcalls()
starts = sorted(byaddr)
import bisect
def lholder(a):
    i = bisect.bisect_right(starts, a) - 1
    return starts[i]
def ldis(name):
    a, n = byname[name]
    print(f"== linux {name} at {a:#x} size {n}")
    callees = []
    for i in md.disasm(lcode[a-lva:a-lva+n], a):
        line = f"  {i.address:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t in byaddr: line += "    -> " + byaddr[t]; callees.append(byaddr[t])
        m = re.search(r"\[e[a-d]x \+ (0x[0-9a-f]+)\]|\[e[a-d]x - (0x[0-9a-f]+)\]", i.op_str)
        if m:
            d = int(m.group(1), 16) if m.group(1) else -int(m.group(2), 16)
            s = lstr(got + d)
            if s: line += "    str " + s
        print(line)
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
known = {}
for m in re.finditer(r'sym\s+"([^"]+)"\s*\n\s*addr\s+"(0x[0-9a-f]+)"', open("gamedata/sigsegv/windows.txt").read()):
    known[m.group(1)] = int(m.group(2), 16)
def wcallees(start, limit=3000):
    out = []
    for n, i in enumerate(md.disasm(code[start-tv:start-tv+limit], base + start)):
        if i.mnemonic == "call" and i.op_str.startswith("0x"): out.append(int(i.op_str, 16) - base)
        if i.mnemonic == "int3": break
    return out
def wdis(start, limit=220):
    print(f"== windows {start:#x}")
    for n, i in enumerate(md.disasm(code[start-tv:start-tv+4000], base + start)):
        line = f"  {i.address-base:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16) - base; line += f"    -> {t:#x}"
            nm = [k for k, v in known.items() if v == t]
            if nm: line += " " + nm[0]
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
    print("  callees of those: " + ", ".join(f"{f:#x}:{n}" for f, n in cc.most_common(15)))
    return cnt, cc

names = ["_ZN15CTFPlayerShared4BurnEP9CTFPlayerP13CTFWeaponBasef",
         "_ZNK15CTFPlayerShared20GetConditionDurationE7ETFCond",
         "_ZN9CTFPlayer20PlaySpecificSequenceEPKc",
         "_ZN17CBaseCombatWeapon7HasAmmoEv",
         "_ZN9CTFPlayer21RemoveCustomAttributeEPKc",
         "_ZN9CTFPlayer18AddCustomAttributeEPKcfb"]
for n in names:
    if n not in byname:
        print("missing", n, [k for k in byname if n[5:25] in k][:5]); continue
    callees, callers = ldis(n)
    cnt, cc = wfind(callees, callers)
    for f, _ in cnt.most_common(2): wdis(f)

# HasAmmo's slot
def rows(path):
    out = []
    for l in open(path):
        if l.startswith("// vtable") and "offset 0x0000" not in l: break
        m = re.match(r'\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)', l)
        if m: out.append((int(m.group(2), 16), m.group(3).strip()))
    return out
def head(va):
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in list(md.disasm(code[va-base-tv:va-base-tv+0x30], va))[:6])
for cls in ("CBaseCombatWeapon", "CTFWeaponBase"):
    try:
        lin = rows(f"derived/linux-vtables/{cls}.txt"); win = rows(f"derived/win-vtables/{cls}.txt")
    except Exception as e:
        print(cls, e); continue
    s = next(i for i, r in enumerate(lin) if "HasAmmo()" in r[1] and "::HasAmmo()" in r[1])
    print(f"== {cls}: linux HasAmmo at slot {s}")
    for i in range(s - 8, s + 8): print(f"  linux {i}: {lin[i][1]}")
    for i in range(s - 16, s + 4): print(f"  windows {i}: 0x{win[i][0]-base:x}  {head(win[i][0])}")
PY
grep -A3 '^"CBaseCombatWeapon::' tools/winport/knownvtidx.generated.txt | grep -E '^"|idx' | paste - - | sort -t'"' -k4 -n
