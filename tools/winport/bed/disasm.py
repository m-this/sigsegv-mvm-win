#!/usr/bin/env python3
"""Print functions of the bed's server.dll into the job log.

The container the port is worked from cannot download the game, and the
Actions runner that installs it cannot hand its files back. This is the way
between: name the RVAs in disasm.txt, and each function is printed with its
calls resolved to RVAs, so the log answers "what does this address call".

    disasm.py server.dll disasm.txt

disasm.txt holds one query per line, `#` for comments:

    0x6e8340              the function at this RVA, to its ret, at most 200 instructions
    0x6e8340 40           at most 40 instructions
    string KeyValues::    every function that references a string containing this
"""

import sys

import capstone
import pefile


def load(path):
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    return pe, base, text


def function(pe, base, text, rva, limit):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    start = rva - text.VirtualAddress
    code = text.get_data()[start:start + limit * 15]
    print(f"== {rva:#x}")
    for count, ins in enumerate(md.disasm(code, base + rva)):
        line = f"  {ins.address - base:#08x}  {ins.mnemonic} {ins.op_str}"
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            line += f"    -> rva {int(ins.op_str, 16) - base:#x}"
        print(line)
        if ins.mnemonic == "ret" or count + 1 >= limit:
            break


def string_refs(pe, base, text, needle):
    data = pe.__data__
    hits = []
    offset = data.find(needle.encode())
    while offset != -1:
        hits.append(offset)
        offset = data.find(needle.encode(), offset + 1)
    code = text.get_data()
    for hit in hits:
        start = data.rfind(b"\0", 0, hit) + 1
        va = base + pe.get_rva_from_offset(start)
        text_value = data[start:data.find(b"\0", start)].decode(errors="replace")
        refs = []
        needle_va = va.to_bytes(4, "little")
        at = code.find(needle_va)
        while at != -1:
            refs.append(text.VirtualAddress + at)
            at = code.find(needle_va, at + 1)
        print(f"== string {text_value!r} at rva {va - base:#x}: referenced from " +
              ", ".join(f"{r:#x}" for r in refs))


def main():
    pe, base, text = load(sys.argv[1])
    for raw in open(sys.argv[2]):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("string "):
            string_refs(pe, base, text, line[len("string "):])
            continue
        parts = line.split()
        function(pe, base, text, int(parts[0], 16), int(parts[1]) if len(parts) > 1 else 200)


main()
