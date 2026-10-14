#!/usr/bin/env python3
"""Write a SourceMod Windows signature for a function this port has located.

A SourceMod plugin finds a game function by a byte signature on Windows, where
it uses a symbol on Linux. This port already knows where many of those
functions are, so the signature can be cut from the bytes rather than reversed
by hand.

    winsig.py server.dll wanted.json

wanted.json is a list of {"name", "sym", "rva"}. For each one it takes
instructions from the function start until the pattern is long enough, replaces
every operand that carries an address with the \\x2A wildcard SourceMod reads,
and then checks the pattern matches exactly once in .text. A pattern that
matches twice, or not at all, is reported and not emitted: SourceMod would
either take the wrong function or fail at load.

Wildcarding is the whole difficulty. A call's rel32 is relative to its own
address, a global's absolute address moves with the image base, so both have to
go; the opcodes and the register fields are what identify the function.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import capstone  # noqa: E402
import matchfuncs as mf  # noqa: E402

MIN_BYTES = 20
MAX_INSTRUCTIONS = 40
WILDCARD = 0x2A


def instructions_from(windows, decoder, address):
    """Decoded instructions from a function start, as (bytes, keep-mask) pairs.

    An operand is wildcarded by its position in the encoding rather than by
    guessing: capstone gives the offset and size of the immediate and of the
    displacement, and those are the only fields that carry an address.
    """
    start = address - windows.text_start
    code = windows.text_bytes[start:start + MAX_INSTRUCTIONS * 16]
    out = []
    for _, instruction in zip(range(MAX_INSTRUCTIONS), decoder.disasm(code, address)):
        raw = bytearray(instruction.bytes)
        keep = bytearray(b"\x01" * len(raw))
        # rel32 branches and calls: the target moves with the function, so
        # everything after the opcode goes.
        if instruction.mnemonic in ("call", "jmp") or instruction.mnemonic.startswith("j"):
            for index in range(1, len(raw)):
                keep[index] = 0
        else:
            encoding = getattr(instruction, "encoding", None)
            if encoding is not None:
                for offset, size in ((encoding.disp_offset, encoding.disp_size),
                                     (encoding.imm_offset, encoding.imm_size)):
                    if size:
                        for index in range(offset, min(offset + size, len(raw))):
                            keep[index] = 0
        out.append((bytes(raw), bytes(keep)))
    return out


def occurrences(haystack, pattern, mask, limit=3):
    """Where the masked pattern matches, up to limit."""
    found, start = [], 0
    first = pattern[0]
    while len(found) < limit:
        index = haystack.find(bytes([first]), start)
        if index < 0 or index + len(pattern) > len(haystack):
            break
        if all(not mask[i] or haystack[index + i] == pattern[i] for i in range(len(pattern))):
            found.append(index)
        start = index + 1
    return found


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    windows = mf.Windows(sys.argv[1])
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    text = windows.text_bytes

    good, bad = [], []
    for row in json.load(open(sys.argv[2])):
        address = row["rva"] + windows.base
        decoded = instructions_from(windows, decoder, address)
        if not decoded:
            bad.append((row["name"], "nothing decoded"))
            continue
        expected = address - windows.text_start
        # Grow the pattern an instruction at a time until it names one place.
        # A prologue several functions share is the common case, and stopping
        # at a fixed length would emit a signature SourceMod resolves to the
        # wrong function.
        pattern = mask = b""
        hits = []
        for raw, keep in decoded:
            pattern += raw
            mask += keep
            if len(pattern) < MIN_BYTES:
                continue
            hits = occurrences(text, pattern, mask)
            if len(hits) == 1:
                break
        if len(hits) != 1:
            bad.append((row["name"], f"{len(hits) or 'no'} matches after {len(pattern)} bytes"))
            continue
        if hits[0] != expected:
            bad.append((row["name"], "the only match is a different function"))
            continue
        escaped = "".join(
            f"\\x{byte:02X}" if keep else f"\\x{WILDCARD:02X}"
            for byte, keep in zip(pattern, mask))
        good.append((row["name"], escaped, len(pattern)))

    for name, escaped, length in good:
        print(f'\t\t\t"{name}"')
        print("\t\t\t{")
        print('\t\t\t\t"library" "server"')
        print(f'\t\t\t\t"windows" "{escaped}"')
        print("\t\t\t}")
        print()
    print(f"{len(good)} unique, {len(bad)} refused", file=sys.stderr)
    for name, why in bad:
        print(f"  refused {name}: {why}", file=sys.stderr)


if __name__ == "__main__":
    main()
