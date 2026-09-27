#!/bin/bash
# The Linux bodies of seven functions the attribute callbacks reach
# unresolved, their Linux callers, and the weapon and filter slots around
# GetViewModel and SetViewModel, Linux names against the Windows heads.
so=game-linux/tf/bin/server_srv.so
syms="_ZNK17CBaseCombatWeapon12GetViewModelEi _ZN17CBaseCombatWeapon12SetViewModelEv _ZN17CBaseCombatWeapon18SetCustomViewModelEPKc _ZNK13CTFWeaponBase12GetViewModelEi _ZNK14CAttributeList18GetAttributeByNameEPKc _ZNK18CEconItemAttribute13GetStaticDataEv _ZN11CBaseFilter12PassesFilterEP11CBaseEntityS1_ _Z14TE_TFExplosionR16IRecipientFilterfRK6VectorS3_iiiii"
for s in $syms; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -150
done
objdump -d --no-show-raw-insn -M intel "$so" > /tmp/linux.dis
for s in $syms; do
  echo "== linux callers of $s"
  awk -v s="<$s>" '/^[0-9a-f]+ <.*>:$/ {f=$2} index($0, "call") && index($0, s) {print f}' /tmp/linux.dis | sort | uniq -c | sort -rn | head -30
done
python3 - <<'PY'
import re, os, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def rows(path):
    out = []
    for l in open(path):
        if l.startswith("// vtable") and "offset 0x0000" not in l: break
        m = re.match(r'\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)', l)
        if m: out.append((int(m.group(2), 16), m.group(3).strip()))
    return out
def head(va, n=10):
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in list(md.disasm(code[va - tva:va - tva + 0x60], va))[:n])
for cls, fns in [("CBaseCombatWeapon", ["GetViewModel", "SetViewModel"]), ("CTFWeaponBase", ["GetViewModel", "SetViewModel"]), ("CTFRocketLauncher", ["GetViewModel", "SetViewModel"]), ("CBaseFilter", ["PassesFilterImpl"])]:
    lp, wp = f"derived/linux-vtables/{cls}.txt", f"derived/win-vtables/{cls}.txt"
    if not (os.path.exists(lp) and os.path.exists(wp)): print(f"=== {cls}: no table"); continue
    lin = rows(lp); win = rows(wp)
    print(f"=== {cls}: linux {len(lin)} slots, windows {len(win)}")
    for fn in fns:
        hits = [i for i, (a, n) in enumerate(lin) if f"::{fn}(" in n]
        if not hits: print(f"  {fn}: not in the Linux table"); continue
        t = hits[0]
        print(f"--- {cls}::{fn} linux slot {t}")
        for s in range(max(0, t - 8), min(len(lin), t + 8)): print(f"  linux {s}: {lin[s][0]:x} {lin[s][1]}")
        for s in range(max(0, t - 14), min(len(win), t + 6)): print(f"  windows {s}: 0x{win[s][0] - base:x}  {head(win[s][0])}")
PY
