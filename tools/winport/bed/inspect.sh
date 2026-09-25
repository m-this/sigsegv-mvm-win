#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
so=game-linux/tf/bin/server_srv.so
for s in _ZN14CAttributeList24SetRuntimeAttributeValueEPK28CEconItemAttributeDefinitionf _ZN9variant_t8SetOtherEPv _ZN17CBaseEntityOutput16ParseEventActionEPKc; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -40
done
# CEconEntity::GiveTo is empty on Linux: the slot where CEconEntity has an
# empty ret 4 and CTFWearable its own code. CTFBonesaw::GetWeaponID is
# `mov eax, 11; ret`: the slots of CTFBonesaw holding exactly that.
python3 - <<'PY'
import pefile, struct, re
pe = pefile.PE("game-windows/tf/bin/server.dll")
base = pe.OPTIONAL_HEADER.ImageBase
def rd(va, n): return pe.get_data(va - base, n)
def vt(c):
    m = re.search(r"vtable at (0x[0-9a-f]+) offset 0x0000", open(f"derived/win-vtables/{c}.txt").read(400))
    return int(m.group(1), 16)
e, w = vt("CEconEntity"), vt("CTFWearable")
for i in range(200, 231):
    fe = struct.unpack("<I", rd(e + 4 * i, 4))[0]; fw = struct.unpack("<I", rd(w + 4 * i, 4))[0]
    print(f"  slot {i}: CEconEntity {fe:#x} {rd(fe, 6).hex(' ')} | CTFWearable {fw:#x} {rd(fw, 6).hex(' ')}")
b = vt("CTFBonesaw")
for i in range(0, 700):
    try: f = struct.unpack("<I", rd(b + 4 * i, 4))[0]; code = rd(f, 6)
    except Exception: break
    if code == bytes.fromhex("b80b000000c3"):
        print(f"CTFBonesaw slot {i}: {f:#x} returns 11")
PY
