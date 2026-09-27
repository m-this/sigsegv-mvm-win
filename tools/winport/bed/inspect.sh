#!/bin/bash
# Linux bodies against the Windows functions the vtables and the matcher
# point at, for the Pop mods' missing detour targets; string and callee
# neighbours for the rest.
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


def lstrings(name):
    a, n = byname[name]; out = []
    for i in md.disasm(lcode[a-lva:a-lva+n], a):
        m = re.search(r"\[e[a-d]x \+ (0x[0-9a-f]+)\]|\[e[a-d]x - (0x[0-9a-f]+)\]", i.op_str)
        if m:
            d = int(m.group(1), 16) if m.group(1) else -int(m.group(2), 16)
            s = lstr(got + d)
            if s and s not in out: out.append(s)
    return out

def compare(sym, rva, ln=55, wn=55):
    print(f"######## {sym} vs {rva:#x}  windows ret {wpop(rva)}")
    try: ldis(sym, ln)
    except Exception as e: print("  linux:", e)
    wdis(rva, wn)

def lite(sym, show=3):
    print(f"######## lite {sym}")
    if sym not in byname: print("  missing"); return
    a, n = byname[sym]
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf): callees, callers = ldis(sym, 0)
    print(f"  linux size {n}, strings {lstrings(sym)[:8]}")
    print(f"  linux callees: {list(dict.fromkeys(callees))[:15]}")
    print(f"  linux callers: {callers[:12]}")
    for s in lstrings(sym)[:4]:
        fs = wrefs(eval(s))
        for f in fs[:4]: print(f"    {f:#x} ret {wpop(f)}  {whead(f, 5)}")
    cnt, cc, kc = wfind(callees, callers)
    for f, k in cnt.most_common(show): print(f"    {f:#x} votes {k} ret {wpop(f)}  {whead(f, 5)}")

pairs = [
 ("_ZN14CSpawnLocation17FindSpawnLocationER6Vector", 0x5ed4e0),
 ("_ZN9CTFPlayer19ReapplyItemUpgradesEP13CEconItemView", 0x508c80),
 ("_ZN9CTFPlayer18GetSceneSoundTokenEv", 0x4f3ff0),
 ("_ZN18CPopulationManager8ResetMapEv", 0x5e69c0),
 ("_ZN18CPopulationManager23UpdateObjectiveResourceEv", 0x5e78c0),
 ("_ZN18CPopulationManager16StartCurrentWaveEv", 0x5e7520),
 ("_ZNK6CTFBot14GetFlagToFetchEv", 0x552180),
 ("_ZNK6CTFBot18GetFlagCaptureZoneEv", 0x552110),
 ("_ZN6CTFBot5SpawnEv", 0x562e50),
 ("_ZN11CBaseEntity6CreateEPKcRK6VectorRK6QAnglePS_", 0x1ee720),
 ("_ZN15CEnvEntityMaker15InputForceSpawnER11inputdata_t", 0x24cd90),
 ("_ZN9CUpgrades5SpawnEv", 0x5f53e0),
 ("_ZN9CUpgradesD0Ev", 0x5f5600),
 ("_ZN11CTFTankBoss14UpdateOnRemoveEv", 0x5f51d0),
 ("_ZN11CTFBaseBoss12OnTakeDamageERK15CTakeDamageInfo", 0x5de570),
 ("_ZN11CTFBaseBoss5TouchEP11CBaseEntity", 0x5df040),
 ("_ZN17CTFBotDeliverFlag5OnEndEP6CTFBotP6ActionIS0_E", 0x588560),
 ("_ZN17CBaseCombatWeapon5EquipEP20CBaseCombatCharacter", 0x1e1080),
 ("_ZN11CTFWearable5EquipEP11CBasePlayer", 0x3d1190),
 ("_ZN12CCaptureFlag16GetMaxReturnTimeEv", 0x448070),
 ("_ZN6CTFBot29GetNearestKnownSappableTargetEv", 0x552da0),
 ("_ZN11CEconEntity14UpdateOnRemoveEv", 0x3a04e0),
 ("_ZN17CBaseCombatWeapon11WeaponSoundE13WeaponSound_tf", 0x1e4d50),
 ("_ZN12CTFGameRules17GetBonusRoundTimeEb", 0x48c300),
 ("_ZN17CTFGCServerSystem15PreClientUpdateEv", 0x5ca630),
]
for sym, rva in pairs:
    compare(sym, rva, 45, 45)

for sym in [
 "_ZN12CCaptureFlag6PickUpEP9CTFPlayerb",
 "_ZN11CTFTankBoss13TankBossThinkEv",
 "_ZN11CTFTankBoss15UpdatePingSoundEv",
 "_ZN11CTFTankBoss16GetCurrencyValueEv",
 "_ZN5CWave12AddClassTypeE8string_tij",
 "_ZN5CWave25IsDoneWithNonSupportWavesEv",
 "_ZN18CPopulationManager7WaveEndEb",
 "_ZN18CPopulationManager24AdjustMinPlayerSpawnTimeEv",
 "_ZN15CEnvEntityMaker11SpawnEntityE6Vector6QAngle",
 "_ZN15CEnvEntityMaker29InputForceSpawnAtEntityOriginER11inputdata_t",
 "_Z18IsSpaceToSpawnHereRK6Vector",
 "_ZN9CTFPlayer10StateLeaveEv",
 "_ZN9CTFPlayer18ShouldDropAmmoPackEv",
 "_ZN9CTFPlayer14IsReadyToSpawnEv",
 "_ZN9CTFPlayer22ShouldGainInstantSpawnEv",
 "_ZN12CTFGameRules19BetweenRounds_ThinkEv",
 "_ZN11CTFBaseBoss22ResolvePlayerCollisionEP9CTFPlayer",
 "_ZN17CObjectTeleporter24RecieveTeleportingPlayerEP9CTFPlayer",
 "_ZN13CTFBaseRocket6CreateEP11CBaseEntityPKcRK6VectorRK6QAngleS1_",
]:
    try: lite(sym)
    except Exception as e: print("  error", e)
for cls, fn in (("VCTFBot____Action", None),):
    win = wrows(cls)
    for k in range(78, 88):
        if k < len(win): print(f"  Action<CTFBot> W[{k}] {win[k]:#x} ret {wpop(win[k])}  {whead(win[k], 5)}")
    for c2 in ("CTFBotScenarioMonitor", "CTFBotTacticalMonitor"):
        w2 = wrows(c2)
        print(f"  {c2} W[82] {w2[82]:#x} W[83] {w2[83]:#x}")
lin = lrows("CTFBotScenarioMonitor")
for k in range(80, 86): print(f"  L[{k}] {lin[k]}")
PY
