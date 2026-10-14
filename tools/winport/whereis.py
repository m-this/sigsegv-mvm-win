#!/usr/bin/env python3
"""Where a Linux global lives in server.dll, for resolving one by hand.

For each Linux function that references the symbol, prints its Windows match
(if any) and every writable-data address that Windows function references, in
order, next to the Linux function's own references with the target marked. A
candidate that every referrer agrees on is usually the answer.

    whereis.py server_srv.so server.dll matches.json SYMBOL
"""

import bisect
import collections
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import matchfuncs as mf  # noqa: E402
from elftools.elf.sections import SymbolTableSection  # noqa: E402

linux = mf.Linux(sys.argv[1])
windows = mf.Windows(sys.argv[2])
matches = json.load(open(sys.argv[3]))
wanted = sys.argv[4]

target = None
for section in linux.elf.iter_sections():
    if isinstance(section, SymbolTableSection):
        for symbol in section.iter_symbols():
            if symbol.name == wanted:
                target = (symbol["st_value"], max(symbol["st_size"], 1))
if target is None:
    raise SystemExit(f"{wanted}: not in the Linux symbol table")

data = windows.sections[".data"]
data_start = windows.base + data.VirtualAddress
data_end = data_start + max(data.Misc_VirtualSize, data.SizeOfRawData)
lbase = linux.text["sh_addr"]
sites = linux.relocation_sites()
votes = collections.Counter()
seen = set()
for site in sites:
    value = struct.unpack_from("<I", linux.text_bytes, site - lbase)[0]
    if not (target[0] <= value < target[0] + target[1]):
        continue
    function = linux.function_of(site)
    if function is None or function in seen:
        continue
    seen.add(function)
    name = linux.functions[function][0]
    match = matches.get(name)
    size = linux.functions[function][1]
    lrefs = []
    for s in sites[bisect.bisect_left(sites, function):bisect.bisect_left(sites, function + size)]:
        v = struct.unpack_from("<I", linux.text_bytes, s - lbase)[0]
        if linux.string_at(v) is None and not linux.functions.get(v) and not (lbase <= v < lbase + linux.text["sh_size"]):
            lrefs.append(("*" if target[0] <= v < target[0] + target[1] else " ") + f"{v:08x}")
    print(f"{name}: {'windows 0x%x (%s)' % (match['rva'] + windows.base, match['via']) if match else 'unmatched'}")
    print("  linux data refs  :", " ".join(lrefs))
    if match:
        w = match["rva"] + windows.base
        k = bisect.bisect_right(windows.starts, w)
        end = windows.starts[k] if k < len(windows.starts) else windows.text_end
        wrefs = [windows.read_u32(s) for s in windows.relocs[bisect.bisect_left(windows.relocs, w):bisect.bisect_left(windows.relocs, end)]]
        wrefs = [v for v in wrefs if data_start <= v < data_end]
        print("  windows data refs:", " ".join(f"{v:08x}" for v in wrefs))
        for v in set(wrefs):
            votes[v] += 1
print("\nwindows addresses by how many matched referrers use them:")
for v, n in votes.most_common(8):
    print(f"  0x{v:08x}  rva 0x{v - windows.base:x}  {n}")
