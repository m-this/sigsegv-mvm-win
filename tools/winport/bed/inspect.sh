#!/bin/bash
# Where each unresolved global lives on Windows: every Linux function that
# references it, next to its matched Windows counterpart's data references.
cd "$(dirname "$0")/../../.." || exit 1
python3 - <<'PY'
import bisect, collections, json, struct, sys
sys.path.insert(0, "tools/winport")
import capstone
import matchfuncs as mf
from elftools.elf.sections import SymbolTableSection

TARGETS = """
g_EventQueue
_ZN19IBaseObjectAutoList29m_IBaseObjectAutoListAutoListE
_ZN19CWaveSpawnPopulator25m_reservedPlayerSlotCountE
g_hUpgradeEntity
g_pMonsterResource
g_hControlPointMasters
lagcompensation
_ZL24g_LagCompensationManager
g_pScriptVM
_ZL33g_RecipientFilterPredictionSystem
_ZL16s_lastTeleporter
_ZN21ICurrencyPackAutoList31m_ICurrencyPackAutoListAutoListE
_ZN20ICaptureZoneAutoList30m_ICaptureZoneAutoListAutoListE
_ZN24ITFBotHintEntityAutoList34m_ITFBotHintEntityAutoListAutoListE
_ZN23IBaseProjectileAutoList33m_IBaseProjectileAutoListAutoListE
_ZN22ITFFlameEntityAutoList32m_ITFFlameEntityAutoListAutoListE
_ZN15IZombieAutoList25m_IZombieAutoListAutoListE
_ZN8CNavArea14m_masterMarkerE
g_TFClassViewVectors
_ZL13g_WorldEntity
PackRatios
_ZL12g_DeleteList
_ZL26s_RemoveImmediateSemaphore
g_bDisableEhandleAccess
g_SentGameRulesMasks
_ZN11CBaseEntity29m_nPredictionRandomSeedServerE
_ZN11CBaseEntity19m_pPredictionPlayerE
g_pFullFileSystem
steamgameserverapicontext
g_szBotModels
g_szBotBossModels
g_szPlayerRobotModels
g_szBotBossSentryBusterModel
g_aClassNames
g_aRawPlayerClassNamesShort
_ZL11s_TankModel
_ZL15s_TankModelRome
g_szLoadoutStrings
g_szRomePromoItems_Hat
g_szRomePromoItems_Misc
g_aTeamColors
s_acttableMelee
_ZL28g_CBaseCombatWeapon_ClassReg
g_aConditionNames
""".split()

linux = mf.Linux("game-linux/tf/bin/server_srv.so")
windows = mf.Windows("game-windows/tf/bin/server.dll")
matches = json.load(open("derived/matches.json"))
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

objects, by_obj_name = {}, {}
for section in linux.elf.iter_sections():
    if isinstance(section, SymbolTableSection):
        for s in section.iter_symbols():
            if s["st_info"]["type"] == "STT_OBJECT" and s["st_value"] and s["st_shndx"] != "SHN_UNDEF":
                objects.setdefault(s["st_value"], (s.name, max(s["st_size"], 1)))
                by_obj_name.setdefault(s.name, (s["st_value"], max(s["st_size"], 1)))
starts = sorted(objects)

def lobj(v):
    i = bisect.bisect_right(starts, v) - 1
    if i < 0:
        return None
    name, size = objects[starts[i]]
    return (name, v - starts[i]) if v < starts[i] + size else None

data = windows.sections[".data"]
dstart = windows.base + data.VirtualAddress
dend = dstart + max(data.Misc_VirtualSize, data.SizeOfRawData)
lbase = linux.text["sh_addr"]
lsites = linux.relocation_sites()
refs_to = collections.defaultdict(list)
for site in lsites:
    o = lobj(struct.unpack_from("<I", linux.text_bytes, site - lbase)[0])
    if o:
        f = linux.function_of(site)
        if f is not None:
            refs_to[o[0]].append(f)
known = {}
for name, m in matches.items():
    if name in by_obj_name:
        known[name] = m["rva"] + windows.base

def insns(code, addr):
    return list(cs.disasm(code, addr))

def at(ins, site):
    for i in ins:
        if i.address <= site < i.address + i.size:
            return f"{i.mnemonic} {i.op_str}"
    return "?"

def lrefs(f):
    size = linux.functions[f][1]
    ins = insns(linux.text_bytes[f - lbase:f + size - lbase], f)
    i, j = bisect.bisect_left(lsites, f), bisect.bisect_left(lsites, f + size)
    out = []
    for site in lsites[i:j]:
        o = lobj(struct.unpack_from("<I", linux.text_bytes, site - lbase)[0])
        if o:
            out.append((o, at(ins, site)))
    return out

def wrefs(w):
    k = bisect.bisect_right(windows.starts, w)
    end = min(windows.starts[k] if k < len(windows.starts) else windows.text_end, w + 0x4000)
    ins = insns(windows.text_bytes[w - windows.text_start:end - windows.text_start], w)
    a, b = bisect.bisect_left(windows.relocs, w), bisect.bisect_left(windows.relocs, end)
    out = []
    for site in windows.relocs[a:b]:
        v = windows.read_u32(site)
        if dstart <= v < dend:
            out.append((v, at(ins, site)))
    return out, end - w

for target in TARGETS:
    if target not in by_obj_name:
        print(f"\n######## {target}: no Linux object")
        continue
    addr, size = by_obj_name[target]
    print(f"\n######## {target}  linux {addr:#x} size {size:#x}  matches.json: {matches.get(target)}")
    funcs = sorted(set(refs_to[target]), key=lambda f: linux.functions[f][1])
    votes = collections.Counter()
    shown = 0
    for f in funcs:
        name, fsize = linux.functions[f]
        m = matches.get(name)
        if not m:
            continue
        w = m["rva"] + windows.base
        L = lrefs(f)
        W, wsize = wrefs(w)
        # Refs to objects the table already places come off both sides.
        Lu, Wu = [], list(W)
        for (o, off), text in L:
            if o in known and o != target:
                hit = next((x for x in Wu if x[0] == known[o] + off), None)
                if hit:
                    Wu.remove(hit)
                    continue
            Lu.append(((o, off), text))
        prop = None
        if len(Lu) == len(Wu) and Lu:
            prop = [(wv - off) for ((o, off), _), (wv, _) in zip(Lu, Wu) if o == target]
            for p in prop:
                votes[p - windows.base] += 1
        if shown < 8:
            shown += 1
            print(f"  L {name} size {fsize:#x}  ->  W {m['rva']:#x} ({m.get('via')}) span {wsize:#x}")
            for (o, off), text in L:
                print(f"     L {o}+{off:#x}: {text}")
            for v, text in W:
                print(f"     W {v - windows.base:#x}: {text}")
            print(f"     unknown left: L {len(Lu)} W {len(Wu)}  proposes {[hex(p - windows.base) for p in prop] if prop else None}")
    unmatched = [linux.functions[f][0] for f in funcs if linux.functions[f][0] not in matches]
    print(f"  referenced by {len(funcs)} Linux functions, {len(funcs) - len(unmatched)} matched; votes {[(hex(k), n) for k, n in votes.most_common(5)]}")
    print(f"  unmatched: {unmatched[:12]}")
PY
