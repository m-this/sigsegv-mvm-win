"""Dump the Linux server's vtables, from its own symbol table.

The dumps under mvm-reversed/Useful/vtable were made against some past build and
say so nowhere. Against a current server.dll they disagree for reasons that look
like the ABI and are not: CGenericFlexCycler has one vtable on each side and
still differs by ten slots, which no ABI rule explains and a game update does.
Matching a stale table against a current one can only ever succeed for the
classes Valve has not touched since, so the fix is a dump of the same build.

server_srv.so keeps its symbols, which is the whole reason SigMod resolves
anything on Linux, so this needs no reversing at all: _ZTV<class> is the vtable
and every slot in it points at a function the symbol table names.

An Itanium vtable holds one sub-table per base subobject, each of them

    [offset-to-top][typeinfo*][slot][slot]...

with offset-to-top zero or negative. That shape is what marks the boundaries,
and it is written out here the way dumpvtables.py writes the Windows locator
offset, so the two sides can be compared sub-table by sub-table rather than as
one flat run.

    python3 dumplinuxvtables.py server_srv.so out_dir/
"""

import hashlib
import re
import struct
import subprocess
import sys
from pathlib import Path

# 32-bit little-endian, which is what a TF2 dedicated server is.
WORD = 4


def symbols(binary):
    """address -> name, and the vtable symbols, out of the binary's own table."""
    out = subprocess.run(
        ["nm", "--defined-only", str(binary)],
        capture_output=True, text=True, check=True,
    ).stdout

    by_address, vtables = {}, []
    for line in out.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) != 3:
            continue
        address, kind, name = parts
        try:
            at = int(address, 16)
        except ValueError:
            continue
        # A function address can carry several names; the first wins, so a
        # dump is stable between runs rather than following nm's order.
        by_address.setdefault(at, name)
        if name.startswith("_ZTV"):
            vtables.append((at, name))
    return by_address, sorted(set(vtables))


def sections(binary):
    """[(virtual address, size, file offset)], for turning an address into bytes."""
    out = subprocess.run(
        ["readelf", "-S", "-W", str(binary)],
        capture_output=True, text=True, check=True,
    ).stdout

    found = []
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+\S+\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            va, off, size = (int(g, 16) for g in m.groups())
            if va:
                found.append((va, size, off))
    return found


def reader(data, secs):
    def word(at):
        for va, size, off in secs:
            if va <= at < va + size:
                start = off + (at - va)
                if start + WORD <= len(data):
                    return struct.unpack_from("<I", data, start)[0]
        return None
    return word


def demangle(names):
    """Names as a reader would write them, in one c++filt rather than thousands."""
    if not names:
        return {}
    out = subprocess.run(
        ["c++filt"], input="\n".join(names), capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    if len(out) != len(names):
        raise SystemExit(f"c++filt answered {len(out)} lines for {len(names)} names")
    return dict(zip(names, out))


def subtables(word, start, limit, code_names):
    """The sub-tables inside one _ZTV symbol, as [(offset-to-top, [addresses])].

    A sub-table opens with its offset-to-top and its typeinfo pointer, so the
    walk ends a table the moment it meets the next pair rather than running on
    into it the way a flat walk does.
    """
    tables, at = [], start
    while at < limit:
        top = word(at)
        info = word(at + WORD)
        if top is None or info is None:
            break
        # offset-to-top is zero for the primary table and negative for the
        # rest, which as an unsigned word is a very large number.
        signed = top - (1 << 32) if top >= (1 << 31) else top
        if signed > 0:
            break
        slots, cursor = [], at + 2 * WORD
        while cursor < limit:
            fn = word(cursor)
            if fn is None or fn not in code_names:
                break
            slots.append(fn)
            cursor += WORD
        if not slots:
            break
        tables.append((-signed, slots))
        at = cursor
    return tables


def filename(pretty):
    """A file per class, and a short one: a deeply templated name is longer than
    a filesystem takes, so those keep a readable head and a hash of the whole."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", pretty)
    if len(safe) <= 120:
        return safe
    return safe[:100] + "-" + hashlib.sha1(pretty.encode()).hexdigest()[:12]


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(2)

    binary, outdir = Path(sys.argv[1]), Path(sys.argv[2])
    data = binary.read_bytes()
    by_address, vtable_symbols = symbols(binary)
    secs = sections(binary)
    word = reader(data, secs)
    print(f"{binary.name}: {len(by_address)} named addresses, {len(vtable_symbols)} vtables")

    # Where each vtable symbol ends: the next symbol along, since nm gives no
    # size for these. The last one runs to the end of its section.
    starts = sorted(a for a, _ in vtable_symbols)
    ends = {}
    for index, at in enumerate(starts):
        after = starts[index + 1] if index + 1 < len(starts) else None
        if after is None:
            after = next((va + size for va, size, _ in secs if va <= at < va + size), at + 0x4000)
        ends[at] = after

    code = set(by_address)
    names = demangle([n for _, n in vtable_symbols])
    functions = demangle(sorted({n for n in by_address.values()}))

    outdir.mkdir(parents=True, exist_ok=True)
    written, total = 0, 0
    for at, symbol in vtable_symbols:
        tables = subtables(word, at, ends[at], code)
        if not tables:
            continue
        pretty = names[symbol].removeprefix("vtable for ")
        lines = [pretty, ""]
        for offset, slots in tables:
            lines.append(f"// vtable at 0x{at:08x} offset 0x{offset:04x}")
            for index, fn in enumerate(slots):
                named = functions.get(by_address.get(fn, ""), "")
                lines.append(f"+0x{index * WORD:04x}:  {fn:08x}  {named}".rstrip())
            lines.append("")
        (outdir / f"{filename(pretty)}.txt").write_text("\n".join(lines))
        written += 1
        total += sum(len(s) for _, s in tables)
    print(f"wrote {written} files, {total} slots, to {outdir}")


if __name__ == "__main__":
    main()
