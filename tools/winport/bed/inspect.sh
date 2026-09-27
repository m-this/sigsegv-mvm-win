#!/bin/bash
# ED_Alloc: no free edicts. What Entity_Limit_Manager reads in engine.dll
# (CGameServer's fields, ED_Alloc, GetEntityCount), and the entity factories
# Entity_Limit_Manager_Convert_Serverside detours, Windows against Linux.
python3 - <<'PY'
import re, struct, collections, capstone, pefile
from elftools.elf.elffile import ELFFile
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

class PE:
    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.secs = [(s.VirtualAddress, s.get_data(), s.Name.rstrip(b"\0").decode()) for s in self.pe.sections]
        t = next(s for s in self.pe.sections if s.Name.rstrip(b"\0") == b".text")
        self.code = t.get_data(); self.tv = t.VirtualAddress
    def bytes(self, rva, n):
        for va, d, _ in self.secs:
            if va <= rva < va + len(d): return d[rva-va:rva-va+n]
        return b""
    def u32(self, rva): return int.from_bytes(self.bytes(rva, 4), "little")
    def start(self, rva):
        at = rva - self.tv
        while at > 0 and not (self.code[at-1] in (0xCC, 0x90) and self.code[at-2] in (0xCC, 0x90)): at -= 1
        return self.tv + at
    def dis(self, rva, limit=80, stop_int3=True, title=None):
        print(f"== {title or ''} {rva:#x}")
        for n, i in enumerate(md.disasm(self.code[rva-self.tv:rva-self.tv+8000], self.base + rva)):
            line = f"  {i.address-self.base:#x}  {i.mnemonic} {i.op_str}"
            if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
                line += f"    -> {int(i.op_str,16)-self.base:#x}"
            for m in re.finditer(r"0x[0-9a-f]{8}", i.op_str):
                v = int(m.group(0), 16) - self.base
                b = self.bytes(v, 60); e = b.find(b"\0")
                if e > 3 and all(32 <= c < 127 for c in b[:e]): line += "    str " + repr(b[:e].decode())
            print(line)
            if (stop_int3 and i.mnemonic == "int3") or n >= limit: break
    def vtable(self, name):
        """MSVC RTTI: type descriptor name -> complete object locator -> vtable (rva)."""
        needle = name.encode() + b"\0"
        out = []
        for va, d, sn in self.secs:
            at = d.find(needle)
            while at != -1:
                td = self.base + va + at - 8
                for va2, d2, sn2 in self.secs:
                    k = d2.find(td.to_bytes(4, "little"))
                    while k != -1:
                        col = va2 + k - 12
                        if self.u32(col) == 0 and self.u32(col + 4) == 0:
                            colva = (self.base + col).to_bytes(4, "little")
                            for va3, d3, sn3 in self.secs:
                                j = d3.find(colva)
                                while j != -1:
                                    out.append(va3 + j + 4); j = d3.find(colva, j + 1)
                        k = d2.find(td.to_bytes(4, "little"), k + 1)
                at = d.find(needle, at + 1)
        return out

class ELF:
    def __init__(self, path):
        self.elf = ELFFile(open(path, "rb"))
        t = self.elf.get_section_by_name(".text")
        self.code = t.data(); self.va = t["sh_addr"]
        self.byname, self.byaddr = {}, {}
        for s in self.elf.get_section_by_name(".symtab").iter_symbols():
            if s["st_value"]:
                self.byname[s.name] = (s["st_value"], s["st_size"])
                if s["st_info"]["type"] == "STT_FUNC": self.byaddr.setdefault(s["st_value"], s.name)
    def dis(self, name, limit=80):
        if name not in self.byname: print("== linux missing", name); return
        a, n = self.byname[name]
        print(f"== linux {name} at {a:#x} size {n}")
        for k, i in enumerate(md.disasm(self.code[a-self.va:a-self.va+n], a)):
            line = f"  {i.address:#x}  {i.mnemonic} {i.op_str}"
            if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
                t = int(i.op_str, 16)
                if t in self.byaddr: line += "    -> " + self.byaddr[t]
            print(line)
            if k >= limit: break

print("######## CServerTools")
s = PE("game-windows/tf/bin/server.dll")
for name in (".?AVCServerTools@@",):
    for vt in s.vtable(name):
        print(f"{name} vtable at {vt:#x}")
        for k in range(16, 24):
            f = s.u32(vt + 4*k) - s.base
            print(f"--- slot {k} -> {f:#x}")
            s.dis(f, 30)
# the matcher's CBaseEntity::Remove (turned away) and UTIL_Remove candidates
s.dis(0x1f8b90, 60, title="Remove candidate")
s.dis(0x2477c0, 150, title="UTIL_Remove candidate")
PY
