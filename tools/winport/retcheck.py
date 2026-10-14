#!/usr/bin/env python3
"""Check a resolved thunk's calling convention against the function it points at.

The tree calls a STATIC_FUNC thunk as __cdecl: the caller cleans the stack. A
Windows function compiled __stdcall, __thiscall or __fastcall cleans its own,
and ends `ret N` rather than `ret`. Calling one through a __cdecl thunk leaves
N bytes of rubbish on the stack at every call, which is a crash somewhere else,
later, and nothing checks for it.

AllocPooledString_StaticConstantStringPointer is the worked example: MSVC
compiled it as a member with the pool in ecx while the tree calls it as a free
function, and including it killed a server mid-mission.

    retcheck.py server.dll sig_list_linkage.txt sig_list_addrs.txt

The linkage dump carries runtime addresses, so the load base is derived from
the two dumps together: an address that windows.txt pins to a fixed offset
appears in sig_list_addrs at base plus that offset, and 858 of them agree.

Reads the linkage dump for the addresses the extension actually resolved, walks
each function to its first return, and reports the ones that do not end `ret`.
A MEMBER_FUNC is expected to end `ret N` on Windows, so only STATIC_FUNC is a
finding; the rest are printed as a count.
"""

import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import capstone  # noqa: E402
import matchfuncs as mf  # noqa: E402

MAX_INSTRUCTIONS = 400


def first_return(windows, decoder, address):
    """The first `ret` an ordinary walk reaches, and how many bytes it pops.

    A walk, not a decode of the whole function: following jumps would need the
    basic blocks and every epilogue of one function agrees about who cleans the
    stack, which is the only thing being asked here.
    """
    offset = address - windows.text_start
    code = windows.text_bytes[offset:offset + MAX_INSTRUCTIONS * 8]
    for _, instruction in zip(range(MAX_INSTRUCTIONS), decoder.disasm(code, address)):
        if instruction.mnemonic == "ret":
            operand = instruction.op_str.strip()
            return int(operand, 0) if operand else 0
        if instruction.mnemonic in ("jmp", "int3") and not instruction.op_str.startswith("0x"):
            return None
    return None


def load_base(windows, addrs_path):
    """Where the loader put server.dll, from the addresses it resolved.

    Every `fixed` entry is base plus a known offset, so the difference the most
    resolved addresses agree on is the base.
    """
    root = Path(__file__).resolve().parents[2]
    text = open(root / "gamedata/sigsegv/windows.txt", encoding="utf-8", errors="replace").read()
    fixed = {
        m[1]: int(m[2], 16)
        for m in re.finditer(
            r'"([^"]+)"\s*\n\s*\{\s*\n\s*type\s+"fixed"\s*\n(?:[^}]*?)addr\s+"0x([0-9a-fA-F]+)"', text)
    }
    deltas = collections.Counter()
    for line in open(addrs_path, encoding="utf-8", errors="replace"):
        m = re.match(r"^(\S+)\s+([0-9a-f]{8,9})\s+(\S.*?)\s*$", line)
        if m and m[1] == "server" and m[3] in fixed:
            deltas[int(m[2], 16) - fixed[m[3]]] += 1
    if not deltas:
        sys.exit("cannot derive the load base: no fixed address resolved")
    base, agree = deltas.most_common(1)[0]
    print(f"// load base 0x{base:08x}, {agree} resolved addresses agree", file=sys.stderr)
    return base


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    windows = mf.Windows(sys.argv[1])
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    base = load_base(windows, sys.argv[3])

    rows = []
    for line in open(sys.argv[2], encoding="utf-8", errors="replace"):
        match = re.match(r"^(\w+)\s+0x([0-9a-f]+)\s+(\S.*?)\s*$", line)
        if not match:
            continue
        kind, runtime, name = match[1], int(match[2], 16), match[3]
        if runtime == 0:
            continue
        address = runtime - base + windows.base
        if not windows.in_text(address):
            continue
        rows.append((kind, address, name, first_return(windows, decoder, address)))

    counts = collections.Counter()
    findings = []
    for kind, address, name, pops in rows:
        counts[kind] += 1
        if pops is None:
            counts[kind + " unreadable"] += 1
            continue
        if kind == "STATIC_FUNC" and pops:
            findings.append((name, address, pops))
        if kind == "MEMBER_FUNC" and pops == 0:
            counts["MEMBER_FUNC ending plain ret"] += 1

    for key, n in sorted(counts.items()):
        print(f"{n:5}  {key}")
    print(f"\nSTATIC_FUNC thunks whose target cleans its own stack: {len(findings)}")
    for name, address, pops in sorted(findings, key=lambda r: -r[2]):
        print(f"  ret 0x{pops:<3x} 0x{address:08x}  {name}")
    print("\nEach one is called __cdecl and is not. Give the thunk the convention"
          "\nits target has, or block the address the way overrides.json does.")


if __name__ == "__main__":
    main()
