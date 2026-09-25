#!/usr/bin/env python3
"""Print functions of the bed's game binaries into the job log.

The container the port is worked from cannot download the game, and the
Actions runner that installs it cannot hand its files back. This is the way
between: name addresses in disasm.txt, and each is printed with its calls
resolved to RVAs, so the log answers "what is at this address".

    disasm.py GAME_DIR disasm.txt

disasm.txt holds one query per line, `#` for comments. The first word names
the module (server, engine, or a path under GAME_DIR); the address is an RVA
or an export plus an offset, as cdb prints a frame in a module it has no
symbols for:

    server 0x6e8340              the function at this RVA, at most 200 instructions
    server 0x6e8340 40           at most 40
    server CreateInterface+0x989e    the function holding that address, through it
    server +0x2ef182             the same for an RVA, as collect.ps1 prints a return address
    server string KeyValues::    the functions referencing a string containing this
    server func 0x408e1f 300     the whole function holding this address, from its start
    server callers 0x21ca90      every direct call to this RVA, each with the function holding it
"""

import os
import sys

import capstone
import pefile

MODULES = {"server": "tf/bin/server.dll", "engine": "bin/engine.dll"}


class Module:
    def __init__(self, path):
        self.pe = pefile.PE(path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.text = next(s for s in self.pe.sections if s.Name.rstrip(b"\0") == b".text")
        self.code = self.text.get_data()
        self.exports = {}
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.name:
                    self.exports[sym.name.decode()] = sym.address

    def rva(self, expr):
        if "+" in expr:
            name, off = expr.split("+", 1)
            return (self.exports[name] if name else 0) + int(off, 16)
        return int(expr, 16)

    def function_start(self, rva):
        """The start of the function holding rva: back to the int3 or nop
        padding MSVC puts between functions, then forward past it."""
        at = rva - self.text.VirtualAddress
        while at > 0 and not (self.code[at - 1] in (0xCC, 0x90) and self.code[at - 2] in (0xCC, 0x90)):
            at -= 1
        return self.text.VirtualAddress + at

    def disasm(self, start, stop_after=None, limit=200):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        at = start - self.text.VirtualAddress
        code = self.code[at:at + 8000]
        print(f"== {start:#x}" + (f" (holding {stop_after:#x}, the 45 instructions before it)" if stop_after else ""))
        lines = []
        for count, ins in enumerate(md.disasm(code, self.base + start)):
            rva = ins.address - self.base
            mark = " <==" if stop_after is not None and rva < stop_after <= rva + ins.size else ""
            line = f"  {rva:#08x}  {ins.mnemonic} {ins.op_str}{mark}"
            if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
                line += f"    -> {int(ins.op_str, 16) - self.base:#x}"
            lines.append(line)
            if stop_after is not None:
                if rva >= stop_after + 24:
                    break
            elif ins.mnemonic == "ret" or count + 1 >= limit:
                break
            if count + 1 >= 2000:
                break
        if stop_after is not None:
            marked = next((i for i, l in enumerate(lines) if l.endswith("<==") or "<==" in l), len(lines))
            lines = lines[max(0, marked - 45):]
        print("\n".join(lines))

    def calls_after(self, needle):
        """Where a function pushes this exact string, the first call that
        follows: for SetContextThink(func, time, "Context") it is ThinkSet."""
        data = self.pe.__data__
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        seen = {}
        offset = data.find(needle.encode() + b"\0")
        while offset != -1:
            if data[offset - 1] == 0:
                ref = (self.base + self.pe.get_rva_from_offset(offset)).to_bytes(4, "little")
                at = self.code.find(b"\x68" + ref)
                while at != -1:
                    for ins in md.disasm(self.code[at:at + 60], self.base + self.text.VirtualAddress + at):
                        if ins.mnemonic == "call":
                            target = ins.op_str
                            if target.startswith("0x"):
                                target = f"{int(target, 16) - self.base:#x}"
                            seen.setdefault(target, []).append(f"{self.text.VirtualAddress + at:#x}")
                            break
                    at = self.code.find(b"\x68" + ref, at + 1)
            offset = data.find(needle.encode() + b"\0", offset + 1)
        print(f"== first call after push {needle!r}: " + "; ".join(f"{t} from {', '.join(v)}" for t, v in seen.items()))

    def callers(self, target):
        """Every E8 call whose destination is target, with the start of the
        function holding it and how far into it the call is: a thin wrapper
        calls its callee a few bytes in."""
        found = []
        at = self.code.find(b"\xe8")
        while at != -1:
            src = self.text.VirtualAddress + at
            if src + 5 + int.from_bytes(self.code[at + 1:at + 5], "little", signed=True) == target:
                start = self.function_start(src)
                found.append(f"{src:#x} in {start:#x}+{src - start:#x}")
            at = self.code.find(b"\xe8", at + 1)
        print(f"== {len(found)} calls to {target:#x}: " + ", ".join(found))

    def strings(self, needle):
        data = self.pe.__data__
        offset = data.find(needle.encode())
        while offset != -1:
            start = data.rfind(b"\0", 0, offset) + 1
            rva = self.pe.get_rva_from_offset(start)
            text = data[start:data.find(b"\0", start)].decode(errors="replace")
            ref = (self.base + rva).to_bytes(4, "little")
            refs, at = [], self.code.find(ref)
            while at != -1:
                refs.append(self.text.VirtualAddress + at)
                at = self.code.find(ref, at + 1)
            print(f"== string {text!r} at {rva:#x}: referenced from " + ", ".join(f"{r:#x}" for r in refs))
            offset = data.find(needle.encode(), offset + 1)


def main():
    game = sys.argv[1]
    modules = {}
    for raw in open(sys.argv[2]):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name, rest = line.split(None, 1)
        print(f"### {line}")
        try:
            if name not in modules:
                modules[name] = Module(os.path.join(game, MODULES.get(name, name)))
            mod = modules[name]
            if rest.startswith("callafter "):
                mod.calls_after(rest[len("callafter "):])
                continue
            if rest.startswith("string "):
                mod.strings(rest[len("string "):])
                continue
            if rest.startswith("callers "):
                mod.callers(mod.rva(rest.split()[1]))
                continue
            if rest.startswith("func "):
                parts = rest.split()
                mod.disasm(mod.function_start(mod.rva(parts[1])), limit=int(parts[2]) if len(parts) > 2 else 200)
                continue
            parts = rest.split()
            target = mod.rva(parts[0])
            if "+" in parts[0]:
                mod.disasm(mod.function_start(target), stop_after=target)
            else:
                mod.disasm(target, limit=int(parts[1]) if len(parts) > 1 else 200)
        except Exception as error:  # one bad query should not hide the rest
            print(f"   failed: {error!r}")


main()
