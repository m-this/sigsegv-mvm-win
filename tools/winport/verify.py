#!/usr/bin/env python3
"""Show a matched pair side by side, to accept or reject it by reading.

For each symbol: both sizes, strings and first instructions, and how many of
the Linux function's matched callees the Windows function also calls.

    verify.py server_srv.so server.dll matches.json SYMBOL [SYMBOL...]

Uses the call graphs candidates.py caches.
"""

import json
import pickle
import sys
from pathlib import Path

import capstone

sys.path.insert(0, str(Path(__file__).parent))
import matchfuncs as mf  # noqa: E402

linux = mf.Linux(sys.argv[1])
windows = mf.Windows(sys.argv[2])
matches = json.load(open(sys.argv[3]))
lgraph, wgraph = pickle.load(open(Path(sys.argv[3]).with_suffix(".graphs.pickle"), "rb"))
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
lbase = linux.text["sh_addr"]
forward = {linux.by_name[n]: m["rva"] + windows.base for n, m in matches.items() if n in linux.by_name}
lstr, wstr = {}, {}
for text, fs in linux.string_references().items():
    for f in fs:
        lstr.setdefault(f, set()).add(text)
for text, fs in windows.string_references().items():
    for f in fs:
        wstr.setdefault(f, set()).add(text)


def head(code, address, n=10):
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for _, i in zip(range(n), cs.disasm(code, address)))


for symbol in sys.argv[4:]:
    l = linux.by_name[symbol]
    m = matches.get(symbol)
    size = linux.functions[l][1]
    print(f"== {symbol}  via {m and m['via']}")
    print(f"   linux   size {size:5}  strings {sorted(lstr.get(l, ()))[:4]}")
    print(f"           {head(linux.text_bytes[l - lbase:l - lbase + size], l)}")
    if not m:
        continue
    w = m["rva"] + windows.base
    i = windows.starts.index(w) if w in windows.starts else None
    end = windows.starts[i + 1] if i is not None and i + 1 < len(windows.starts) else w + 0x100
    code = windows.text_bytes[w - windows.text_start:w - windows.text_start + (end - w)]
    print(f"   windows size {end - w:5}  strings {sorted(wstr.get(w, ()))[:4]}")
    print(f"           {head(code, w)}")
    lc = [forward[t] for t in set(lgraph.get(l, ())) if t in forward]
    wc = set(wgraph.get(w, ()))
    print(f"   matched callees also called on Windows: {sum(1 for t in lc if t in wc)}/{len(lc)}; windows calls {len(wc)}")
