#!/bin/bash
# CTFGCServerSystem::PreClientUpdate at 0x5ca630, and the IServer/IClient slots
# SigMod's two detours of it call through engine.dll.
echo "=== CTFGCServerSystem vtables"
for f in derived/linux-vtables/CTFGCServerSystem.txt derived/win-vtables/CTFGCServerSystem.txt; do
  echo "--- $f"; head -n 45 "$f"
done
grep -rl "0x5ca630\|105ca630\|0x105ca630" derived/win-vtables | head
python3 tools/winport/dumpvtables.py game-windows/bin/engine.dll /tmp/engvt > /tmp/engvt.log 2>&1
ls /tmp/engvt | grep -i "server\|client" | head -60
python3 - <<'PY'
import re, collections, capstone, pefile, os
from elftools.elf.elffile import ELFFile
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

elf = ELFFile(open("game-linux/tf/bin/server_srv.so", "rb"))
lt = elf.get_section_by_name(".text"); lcode = lt.data(); lva = lt["sh_addr"]
byaddr, byname = {}, {}
for s in elf.get_section_by_name(".symtab").iter_symbols():
    if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
        byaddr.setdefault(s["st_value"], s.name); byname[s.name] = (s["st_value"], s["st_size"])
for name in ["_ZN17CTFGCServerSystem15PreClientUpdateEv", "_ZN15CGCClientSystem15PreClientUpdateEv"]:
    if name not in byname: print("no", name); continue
    a, n = byname[name]
    print(f"== linux {name} at {a:#x} size {n}")
    for i in md.disasm(lcode[a-lva:a-lva+n], a):
        t = ""
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = "    -> " + byaddr.get(int(i.op_str, 16), "?")
        print(f"  {i.address:#x}  {i.mnemonic} {i.op_str}{t}")

class PE:
    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.text = next(s for s in self.pe.sections if s.Name.rstrip(b"\0") == b".text")
        self.code = self.text.get_data(); self.tv = self.text.VirtualAddress
    def dis(self, rva, limit=300, stop_int3=True, label=""):
        print(f"== {label} {rva:#x}")
        n = 0
        for i in md.disasm(self.code[rva-self.tv:rva-self.tv+8000], self.base + rva):
            print(f"  {i.address - self.base:#x}  {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")
            n += 1
            if n >= limit or (stop_int3 and i.mnemonic == "int3"): break
    def callers(self, rva):
        out = []; at = self.code.find(b"\xe8")
        while at != -1:
            dst = self.tv + at + 5 + int.from_bytes(self.code[at+1:at+5], "little", signed=True)
            if dst == rva: out.append(self.tv + at)
            at = self.code.find(b"\xe8", at + 1)
        return out

srv = PE("game-windows/tf/bin/server.dll")
srv.dis(0x5ca630, 260, label="server.dll PreClientUpdate candidate")
print("direct callers of 0x5ca630:", [hex(c) for c in srv.callers(0x5ca630)])
# every place the VA appears as data (a vtable slot)
data = open("game-windows/tf/bin/server.dll", "rb").read()
va = (srv.base + 0x5ca630).to_bytes(4, "little")
print("VA as data at file offsets:", [hex(m.start()) for m in re.finditer(re.escape(va), data)][:10])

eng = PE("game-windows/bin/engine.dll")
def slots(cls, count):
    p = f"/tmp/engvt/{cls}.txt"
    if not os.path.exists(p): print("no", p); return
    print(f"=== engine.dll {cls}")
    rows = open(p).read().splitlines()
    for r in rows[:count + 40]:
        print("  " + r)
    # disassemble the head of each slot of every table listed
    for r in rows:
        m = re.match(r"\+0x([0-9a-f]+):\s+([0-9a-f]+)", r)
        if r.startswith("//"): print(" " + r)
        if not m: continue
        off = int(m.group(1), 16); v = int(m.group(2), 16)
        if off // 4 > count: continue
        heads = []
        for i in md.disasm(eng.code[v-eng.base-eng.tv:v-eng.base-eng.tv+60], v):
            heads.append(f"{i.mnemonic} {i.op_str}")
            if i.mnemonic in ("ret", "jmp") or len(heads) >= 8: break
        print(f"   [{off//4:3d}] {v-eng.base:#x}: " + " ; ".join(heads))
for cls in ["CBaseServer", "CGameServer", "CBaseClient", "CGameClient"]:
    slots(cls, 40)
PY
