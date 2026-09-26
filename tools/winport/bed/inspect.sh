#!/bin/bash
# CBaseProjectile's destructors: slot 0 of it and its subclasses on Windows,
# what each calls, and the Linux D2 body. Then which Linux D2 destructors
# SigMod detours are called from another class's destructor (have subclasses).
python3 - <<'PY'
import re, struct, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def rows(path):
    out = []
    try: f = open(path)
    except OSError: return out
    for l in f:
        if l.startswith("// vtable") and "offset 0x0000" not in l: break
        m = re.match(r'\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)', l)
        if m: out.append((int(m.group(2), 16), m.group(3).strip()))
    return out
def dis(va, n=140, stop=True):
    out = []
    for i in md.disasm(code[va - tva:va - tva + 0x800], va):
        out.append(i)
        if len(out) >= n or (stop and i.mnemonic in ("ret", "jmp") and i.op_str.startswith(("0x", "")) and i.mnemonic == "ret"): break
    return out
def show(label, va, n=140):
    print(f"--- {label} 0x{va - base:x}")
    for i in dis(va, n):
        s = f"{i.mnemonic} {i.op_str}"
        s = re.sub(r'0x([0-9a-f]{8})', lambda m: f"0x{int(m.group(1),16)-base:x}" if int(m.group(1),16) >= base else m.group(0), s)
        print(f"   {i.address - base:7x}: {s}")
classes = ["CBaseProjectile", "CTFBaseProjectile", "CTFBaseRocket", "CTFProjectile_Rocket",
           "CTFProjectile_Arrow", "CTFProjectile_Flare", "CTFProjectile_EnergyBall",
           "CBaseGrenade", "CTFWeaponBaseGrenadeProj", "CTFGrenadePipebombProjectile",
           "CTFProjectile_Jar", "CTFProjectile_SentryRocket", "CBaseAnimating"]
seen = set()
for c in classes:
    w = rows(f"derived/win-vtables/{c}.txt")
    if not w: print(f"{c}: no windows table"); continue
    print(f"== {c} slot0 0x{w[0][0] - base:x}")
    show(f"{c} slot0", w[0][0], 40)
    for i in dis(w[0][0], 40):
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t not in seen and tva <= t < tva + len(code):
                seen.add(t); show(f"  target of {c} slot0", t, 160)
PY
python3 - <<'PY'
import struct, re, capstone, subprocess
data = open("game-linux/tf/bin/server_srv.so", "rb").read()
e_shoff, = struct.unpack_from("<I", data, 0x20)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x2e)
secs = []
for k in range(e_shnum):
    secs.append(struct.unpack_from("<IIIIIIIIII", data, e_shoff + k * e_shentsize))
shstr = secs[e_shstrndx]
def nm(off, stroff):
    end = data.index(b"\0", stroff + off); return data[stroff + off:end].decode()
byname = {s: sec for s, sec in ((nm(sec[0], shstr[4]), sec) for sec in secs)}
syms = {}; addr2 = {}
for tab in (".symtab", ".dynsym"):
    if tab not in byname: continue
    st = byname[tab]; strsec = secs[st[6]]
    for off in range(st[4], st[4] + st[5], 16):
        n, v, sz, info, oth, shn = struct.unpack_from("<IIIBBH", data, off)
        if (info & 0xf) != 2 or v == 0: continue
        s = nm(n, strsec[4]); syms[s] = (v, sz); addr2.setdefault(v, s)
tx = byname[".text"]
def fbytes(v, sz): return data[v - tx[3] + tx[4]: v - tx[3] + tx[4] + sz]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def show(s):
    v, sz = syms[s]; print(f"--- linux {s} 0x{v:x} size {sz}")
    for i in md.disasm(fbytes(v, sz), v):
        o = i.op_str
        if i.mnemonic in ("call", "jmp") and o.startswith("0x"): o += "  " + addr2.get(int(o, 16), "")
        print(f"   {i.address:7x}: {i.mnemonic} {o}")
show("_ZN15CBaseProjectileD2Ev")
if "_ZN15CBaseProjectileD0Ev" in syms: show("_ZN15CBaseProjectileD0Ev")
# which destructors call each detoured D2
want = ["_ZN15CBaseProjectileD2Ev", "_ZN19CTFPointWeaponMimicD2Ev", "_ZN14CTriggerCameraD2Ev",
        "_ZN17CMissionPopulatorD2Ev", "_ZN5CWaveD2Ev", "_ZN19CWaveSpawnPopulatorD2Ev",
        "_ZN12CTankSpawnerD2Ev", "_ZN13CTFBotSpawnerD2Ev", "_ZN23CTFBotEscortSquadLeaderD2Ev",
        "_ZN6CTFBotD2Ev", "_ZN9CUpgradesD2Ev", "_ZN15CHeadlessHatmanD2Ev",
        "_ZN21CTFBotMvMEngineerIdleD2Ev", "_ZN11CBaseEntityD2Ev", "_ZN13CSquadSpawnerD2Ev"]
callers = {w: [] for w in want}
tgt = {syms[w][0]: w for w in want if w in syms}
for s, (v, sz) in syms.items():
    if not re.search(r'D[012]Ev$', s) or sz == 0: continue
    for i in md.disasm(fbytes(v, sz), v):
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t in tgt and s not in callers[tgt[t]]: callers[tgt[t]].append(s)
for w in want:
    if w not in syms: print(f"callers {w}: no symbol"); continue
    c = [x for x in callers[w] if not x.startswith(w[:-3])]
    print(f"callers {w}: {len(c)} other destructors: {' '.join(sorted(c)[:12])}")
PY
