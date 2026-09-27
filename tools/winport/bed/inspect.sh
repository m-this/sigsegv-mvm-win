#!/bin/bash
# The strings 0x4d1a70 pushes, where the VAs of the functions referencing
# "TeleporterContext" are used, and the Linux bodies of FindTarget and
# TeleporterSend beside the Windows ones already read.
python3 - <<'PY'
import re, struct, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
def cstr(va):
    off = va - base
    return img[off:img.index(b"\0", off)].decode("latin1")
for va in (0x108732d8, 0x108732e8, 0x108732b4, 0x108732c4, 0x10873300, 0x109e1d4c, 0x109dc9b4, 0x1087331c,
           0x109de59c, 0x109de360, 0x109de5bc, 0x10860e00, 0x1088d1fc, 0x1088d194):
    try: print(f"  string 0x{va - base:x}: {cstr(va)!r}")
    except Exception as e: print(f"  string 0x{va - base:x}: {e}")
# every function start (after int3/nop padding) whose VA appears as an
# immediate in .text next to a string reference to TeleporterContext
ctx = img.find(b"TeleporterContext\0")
print(f"  TeleporterContext at rva 0x{ctx:x}")
cva = struct.pack("<I", base + ctx)
for m in re.finditer(re.escape(cva), code):
    at = tva + m.start()
    win = code[m.start() - 0x40:m.start()]
    imms = [struct.unpack_from("<I", win, i)[0] for i in range(len(win) - 3)]
    fn = [hex(x - base) for x in imms if tva <= x < tva + len(code) and code[x - tva - 1] in (0xcc, 0x90)]
    print(f"  TeleporterContext pushed at 0x{at - base:x}; code VAs just before it: {fn}")
PY
so=game-linux/tf/bin/server_srv.so
for sym in _ZN16CObjectSentrygun10FindTargetEv _ZN17CObjectTeleporter14TeleporterSendEP9CTFPlayer; do
  line=$(nm -S "$so" 2>/dev/null | grep " $sym\$" | head -1)
  echo "--- $sym: $line"
  [ -z "$line" ] && continue
  addr=$((16#$(echo $line | cut -d' ' -f1))); size=$((16#$(echo $line | cut -d' ' -f2)))
  objdump -d --no-show-raw-insn -C --start-address=$addr --stop-address=$((addr + size)) "$so" | tail -n +7 | head -700 | sed -E 's/<([^>+]{60})[^>]*>/<\1...>/'
done
nm -C "$so" | grep -E "CObjectTeleporter::Teleporter|CObjectSentrygun::(FindTarget|ValidTarget)"
