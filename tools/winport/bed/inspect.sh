#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
so=game-linux/tf/bin/server_srv.so
for s in _ZNK13CTFBaseRocket14GetOwnerPlayerEv _ZN9CTFPlayer33GetEquippedWearableForLoadoutSlotEi _ZN9CTFPlayer11UpdateModelEv _Z17TE_DispatchEffectR16IRecipientFilterfRK6VectorPKcRK11CEffectData; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -70
done
# NextBotPlayer<CTFPlayer>::Release*Button: on Linux `and [this+buttons], ~BIT;
# mov [this+timer], -1.0f; ret`. The Windows bodies by their bytes:
# and dword ptr [ecx+X], imm8/imm32; mov dword ptr [ecx+Y], 0xbf800000; ret
python3 - <<'PY'
import re, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll")
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code, va = text.get_data(), text.VirtualAddress
pat = re.compile(rb"\x83\xa1(....)(.)\xc7\x81(....)\x00\x00\x80\xbf\xc3|\x81\xa1(....)(....)\xc7\x81(....)\x00\x00\x80\xbf\xc3", re.S)
for m in pat.finditer(code):
    if m.group(1):
        buttons, mask, timer = int.from_bytes(m.group(1), "little"), int.from_bytes(m.group(2), "little", signed=True) & 0xffffffff, int.from_bytes(m.group(3), "little")
    else:
        buttons, mask, timer = int.from_bytes(m.group(4), "little"), int.from_bytes(m.group(5), "little"), int.from_bytes(m.group(6), "little")
    print(f"release body at rva {va + m.start():#x}: buttons +{buttons:#x} &= {mask:#010x}, timer +{timer:#x} = -1.0f")
PY
