#!/bin/bash
# Where the unresolved globals live on Windows, second pass: data found by its
# content, pointer tables by the strings they point at, and a few bodies read
# around one reference.
cd "$(dirname "$0")/../../.." || exit 1
python3 - <<'PY'
import bisect, struct, sys
sys.path.insert(0, "tools/winport")
import capstone
import matchfuncs as mf
from elftools.elf.sections import SymbolTableSection

linux = mf.Linux("game-linux/tf/bin/server_srv.so")
win = mf.Windows("game-windows/tf/bin/server.dll")
B = win.base
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

sym = {}
for section in linux.elf.iter_sections():
    if isinstance(section, SymbolTableSection):
        for s in section.iter_symbols():
            if s["st_value"] and s["st_shndx"] != "SHN_UNDEF":
                sym.setdefault(s.name, (s["st_value"], s["st_size"]))

def lbytes(addr, size):
    for s in linux.elf.iter_sections():
        if s["sh_addr"] <= addr < s["sh_addr"] + s["sh_size"] and s["sh_type"] != "SHT_NOBITS":
            return s.data()[addr - s["sh_addr"]:addr - s["sh_addr"] + size]
    return None

def lu32(addr):
    return struct.unpack("<I", lbytes(addr, 4))[0]

wsecs = [(s.Name.rstrip(b"\0").decode(), B + s.VirtualAddress, s.get_data()) for s in win.pe.sections]

def wfind(needle):
    out = []
    for name, va, data in wsecs:
        at = data.find(needle)
        while at >= 0:
            out.append((name, va + at - B))
            at = data.find(needle, at + 1)
    return out

def wread(va, n):
    for name, sva, data in wsecs:
        if sva <= va < sva + len(data):
            return data[va - sva:va - sva + n]
    return b"\0" * n

print("==== A. data found by content")
for name in ["g_szBotModels", "g_szBotBossModels", "g_szPlayerRobotModels", "g_szBotBossSentryBusterModel",
             "g_szRomePromoItems_Hat", "g_szRomePromoItems_Misc", "PackRatios", "g_TFClassViewVectors",
             "g_aTeamColors", "s_acttableMelee"]:
    addr, size = sym[name]
    data = lbytes(addr, size)
    if data is None:
        print(f"{name}: in .bss")
        continue
    hits = wfind(data)
    print(f"{name} size {size:#x} first {data[:40]!r}: full hits {[(n, hex(r)) for n, r in hits]}")
    if not hits:
        print(f"   first 0x40 bytes: {[(n, hex(r)) for n, r in wfind(data[:0x40])][:6]}")
    if name == "s_acttableMelee":
        print("   linux", data[:48].hex())

print("==== B. pointer tables by their strings")
wstr_sites = {}
for site in win.relocs:
    if win.in_text(site):
        continue
    try:
        v = win.read_u32(site)
    except Exception:
        continue
    t = win.string_at(v)
    if t is None:
        raw = wread(v, 64).split(b"\0")[0]
        t = raw.decode("latin-1") if raw and all(32 <= c < 127 for c in raw) else None
    if t is not None:
        wstr_sites[site] = t
sites_sorted = sorted(wstr_sites)
for name in ["g_aClassNames", "g_aRawPlayerClassNamesShort", "_ZL11s_TankModel", "_ZL15s_TankModelRome",
             "g_szLoadoutStrings", "_ZL17g_aConditionNames", "g_aRawPlayerClassNames"]:
    if name not in sym:
        print(f"{name}: no Linux symbol")
        continue
    addr, size = sym[name]
    entries = []
    for i in range(size // 4):
        v = lu32(addr + 4 * i)
        raw = lbytes(v, 80) if v else None
        entries.append(raw.split(b"\0")[0].decode("latin-1") if raw is not None else None)
    print(f"{name} {size // 4} entries: {entries[:14]}")
    first = next(i for i, e in enumerate(entries) if e)
    for site in sites_sorted:
        if wstr_sites[site] != entries[first]:
            continue
        base = site - 4 * first
        got = [wstr_sites.get(base + 4 * i) for i in range(len(entries))]
        same = sum(1 for a, b in zip(got, entries) if a == b)
        if same >= max(2, len(entries) // 2):
            print(f"   at {base - B:#x}: {same}/{len(entries)} agree; windows {got[:14]}")

print("==== C. values in the file")
for rva, n in [(0x9d3134, 4), (0x9a2458, 4), (0x992288, 4), (0x9cd3ac, 12), (0x9c7de0, 24), (0x9d3098, 4)]:
    print(f"   {rva:#x}: {wread(B + rva, n).hex()}")

def text_refs(value):
    code = win.text_bytes
    out, at = [], code.find(struct.pack("<I", value))
    while at >= 0:
        out.append(win.text_start + at)
        at = code.find(struct.pack("<I", value), at + 1)
    return out

def insn_at(site):
    f = win.function_of(site) or site - 0x40
    for i in cs.disasm(win.text_bytes[f - win.text_start:site + 16 - win.text_start], f):
        if i.address <= site < i.address + i.size:
            return f, f"{i.address - B:#x}: {i.mnemonic} {i.op_str}"
    return f, "?"

print("==== D. code naming an address")
for rva in [0x9a2458]:
    for s in text_refs(B + rva)[:20]:
        f, text = insn_at(s)
        print(f"   {rva:#x} in {f - B:#x}  {text}")
for cls in ["CLagCompensationManager", "CRecipientFilterPredictionSystem", "CCurrencyPack"]:
    try:
        rows = open(f"derived/win-vtables/{cls}.txt").read().splitlines()
    except OSError:
        print(f"   {cls}: no table")
        continue
    heads = [r for r in rows if r.startswith("// vtable")]
    print(f"   {cls}: {heads}  slot0 {rows[1] if len(rows) > 1 else ''}")
    for h in heads:
        vt = int(h.split()[3], 16)
        for s in text_refs(vt)[:8]:
            f, text = insn_at(s)
            print(f"      vtable {vt - B:#x} named in {f - B:#x}  {text}")

print("==== E. ServerClass records")
for cname in ["CBaseCombatWeapon", "CBasePlayer", "CBaseCombatCharacter"]:
    for site, t in wstr_sites.items():
        if t == cname and not win.in_text(site):
            print(f"   {cname!r} at {site - B:#x}: {wread(site, 20).hex()}")

print("==== F. around a reference")
def around(func_rva, value, before=10, after=6):
    f = B + func_rva
    k = bisect.bisect_right(win.starts, f)
    end = min(win.starts[k] if k < len(win.starts) else win.text_end, f + 0x3000)
    ins = list(cs.disasm(win.text_bytes[f - win.text_start:end - win.text_start], f))
    pat = f"{B + value:#x}"
    for n, i in enumerate(ins):
        if pat in i.op_str:
            print(f"   -- {func_rva:#x} ref {value:#x}")
            for j in ins[max(0, n - before):n + after]:
                print(f"      {j.address - B:#x}: {j.mnemonic} {j.op_str}")
around(0x1ffc40, 0x97ab88)
around(0x5efcc0, 0xb96664, 8, 4)
around(0x37ab40, 0xa80fb8, 6, 4)

print("==== G. Linux bodies")
def lbody(name, limit=60):
    a = linux.by_name.get(name)
    if a is None:
        print(f"   {name}: none")
        return
    size = linux.functions[a][1]
    print(f"   -- {name} {a:#x} size {size:#x}")
    for n, i in enumerate(cs.disasm(linux.text_bytes[a - linux.text["sh_addr"]:a + size - linux.text["sh_addr"]], a)):
        if n >= limit:
            break
        print(f"      {i.address:#x}: {i.mnemonic} {i.op_str}")
lbody("_ZN13CVoiceGameMgr15ClientConnectedEP7edict_t")
lbody("_ZN11CBaseEntity23SetPredictionRandomSeedEPK8CUserCmd")
lbody("_ZN11CPlayerMove12StartCommandEP11CBasePlayerP8CUserCmd", 40)
lbody("_Z20UTIL_RemoveImmediateP11CBaseEntity")
lbody("_ZN30ISearchSurroundingAreasFunctor20IterateAdjacentAreasEP8CNavAreaS1_f", 30)
PY
