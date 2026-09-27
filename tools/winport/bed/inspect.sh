#!/bin/bash
# Round twelve: candidates common to the known callers of the remaining
# targets; the touch CUpgrades::Spawn sets; CTFBaseBoss' think.
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
        for v in re.findall(r"0x10[0-9a-f]{6}", i.op_str):
            s = wcstr(int(v, 16) - base)
            if s: line += "    str " + s
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


def wcstr(rva):
    for va, data in rdata:
        if va <= rva < va + len(data):
            e = data.find(b"\0", rva - va)
            t = data[rva - va:e]
            if 3 <= len(t) and all(32 <= c < 127 for c in t[:40]): return repr(t[:60].decode())
    return None
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


def viacallers(sym, show=6):
    a, n = byname[sym]
    lc = sorted({byaddr[lholder(s)] for s in lg.get(a, ())})
    kc = [c for c in lc if c in known]
    print(f"######## {sym}: {len(lc)} linux callers, {len(kc)} known on Windows")
    cc = collections.Counter()
    for c in kc:
        for t in set(wcallees(known[c], 0x3000)): cc[t] += 1
    for t, k in cc.most_common(40):
        if k < 2 or t in kname: continue
        if not (tv <= t < tv + len(code)): continue
        print(f"    {t:#x} in {k}/{len(kc)} callers, {len({wstart(s) for s in wg.get(t, ())})} callers in all, ret {wpop(t)} {whead(t, 5)}")
        show -= 1
        if show == 0: break

for s in ["_Z21UTIL_EntitiesInSphereRK6VectorfP20CFlaggedEntitiesEnum",
          "_Z16UTIL_ScreenShakeRK6Vectorffff14ShakeCommand_tb",
          "_Z18IsSpaceToSpawnHereRK6Vector",
          "_ZN9CTFPlayer10StateLeaveEv",
          "_ZN24CTeamplayRoundBasedRules28GetMinTimeWhenPlayerMaySpawnEP11CBasePlayer",
          "_ZN9CTFPlayer18ShouldDropAmmoPackEv",
          "_ZN5CWave25IsDoneWithNonSupportWavesEv",
          "_Z17GetBotEscortCounti",
          "_ZN11CTFBaseBoss22ResolvePlayerCollisionEP9CTFPlayer",
          "_ZN12CEventActionC2EPKc",
          "_ZN18CFlagDetectionZone19EntityIsFlagCarrierEP11CBaseEntity",
          "_ZNK6CTFBot21GetDesiredAttackRangeEv",
          "_ZN16CTFBotMainAction17FireWeaponAtEnemyEP6CTFBot",
          "_ZNK11CTFBotSquad33ShouldSquadLeaderWaitForFormationEv",
          "_ZN21CTFBotTacticalMonitor19AvoidBumpingEnemiesEP6CTFBot",
          "_ZN16CTFWeaponBaseGun10FireRocketEP9CTFPlayeri",
          "_ZN21CHeadlessHatmanAttack21RecomputeHomePositionEv",
          "_ZN15CTFReviveMarker6CreateEP9CTFPlayer",
          "_ZNK15CTFFlameManager19GetFlameDamageScaleEPK10tf_point_tP9CTFPlayer"]:
    try: viacallers(s)
    except Exception as e: print("  error", s, e)
print("######## code pointers in CUpgrades::Spawn 0x5f53e0 and CTFBaseBoss' datamap")
for x in md.disasm(code[0x5f53e0-tv:0x5f53e0-tv+0x200], base + 0x5f53e0):
    if x.mnemonic == "int3": break
    for v in re.findall(r"0x10[0-9a-f]{6}", x.op_str):
        r = int(v, 16) - base
        if tv <= r < tv + len(code): print(f"    {x.address-base:#x} {x.mnemonic} {x.op_str}  -> ret {wpop(r)} {whead(r, 6)}")
def dyninit2(fname, after=40):
    print(f"######## datamap init {fname}")
    for a in wstr(fname):
        pat = (base + a).to_bytes(4, "little")
        at = code.find(pat)
        while at != -1:
            site = tv + at
            f = wstart(site)
            ins = list(md.disasm(code[f-tv:site-tv+0x200], base + f))
            k = next((i for i, x in enumerate(ins) if x.address - base <= site < x.address - base + x.size), None)
            if k is not None:
                for x in ins[max(0, k-30):k+after]:
                    for v in re.findall(r"0x10[0-9a-f]{6}", x.op_str):
                        r = int(v, 16) - base
                        if tv <= r < tv + len(code) and x.mnemonic == "mov": print(f"    {x.address-base:#x}  code {r:#x} ret {wpop(r)} {whead(r, 5)}")
                        elif wcstr(r): print(f"    {x.address-base:#x}  str {wcstr(r)}")
                print("    --")
            at = code.find(pat, at + 1)
for f in ("BossThink", "UpgradeTouch"):
    dyninit2(f, 25)
PY
