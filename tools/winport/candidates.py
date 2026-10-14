#!/usr/bin/env python3
"""Rank server.dll functions that could be a given Linux function.

For resolving one address by hand when matchfuncs.py found nothing. A
candidate scores a point for every matched caller of the Linux function whose
Windows counterpart calls it, and for every matched callee whose counterpart
it calls. The top few are printed with their strings and first instructions,
next to the Linux function's, so the call can be made by reading.

    candidates.py server_srv.so server.dll matches.json SYMBOL [SYMBOL...]

Call graphs are cached next to matches.json.
"""

import collections
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
cache = Path(sys.argv[3]).with_suffix(".graphs.pickle")

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
cs.detail = True
lbase = linux.text["sh_addr"]
if cache.exists():
    lgraph, wgraph = pickle.load(open(cache, "rb"))
else:
    lranges = [(a, a + linux.functions[a][1]) for a in linux.starts if linux.functions[a][1] > 0]
    lgraph = mf.call_graph(cs, lranges, lambda a, b: linux.text_bytes[a - lbase:b - lbase], set(linux.functions))
    ws = windows.starts
    wranges = [(a, min(ws[i + 1] if i + 1 < len(ws) else windows.text_end, a + 0x4000)) for i, a in enumerate(ws)]
    wgraph = mf.call_graph(cs, wranges, lambda a, b: windows.text_bytes[a - windows.text_start:b - windows.text_start], set(ws), windows.in_text)
    pickle.dump((lgraph, wgraph), open(cache, "wb"))


def callers(graph):
    out = collections.defaultdict(set)
    for f, targets in graph.items():
        for t in targets:
            out[t].add(f)
    return out


lcallers, wcallers = callers(lgraph), callers(wgraph)
forward = {linux.by_name[n]: m["rva"] + windows.base for n, m in matches.items() if n in linux.by_name}
backward = {w: l for l, w in forward.items()}
lstrings, wstrings = collections.defaultdict(set), collections.defaultdict(set)
for text, fs in linux.string_references().items():
    for f in fs:
        lstrings[f].add(text)
for text, fs in windows.string_references().items():
    for f in fs:
        wstrings[f].add(text)


def head(code, address, n=8):
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for _, i in zip(range(n), cs.disasm(code, address)))


for symbol in sys.argv[4:]:
    l = linux.by_name.get(symbol)
    if l is None:
        print(f"{symbol}: not in the Linux symbol table\n")
        continue
    size = linux.functions[l][1]
    print(f"== {symbol}  size {size}")
    print(f"   linux strings: {sorted(lstrings[l])[:6]}")
    print(f"   linux head   : {head(linux.text_bytes[l - lbase:l - lbase + size], l)}")
    score = collections.Counter()
    known_callers = [c for c in lcallers.get(l, ()) if c in forward]
    known_callees = [t for t in lgraph.get(l, ()) if t in forward]
    for c in known_callers:
        for t in set(wgraph.get(forward[c], ())):
            if t not in backward:
                score[t] += 1
    for t in set(known_callees):
        for c in wcallers.get(forward[t], ()):
            if c not in backward:
                score[c] += 1
    print(f"   matched callers {len(known_callers)}, matched callees {len(set(known_callees))}")
    for w, points in score.most_common(4):
        k = windows.starts.index(w) if w in windows.starts else None
        end = windows.starts[k + 1] if k is not None and k + 1 < len(windows.starts) else w + 0x200
        code = windows.text_bytes[w - windows.text_start:w - windows.text_start + min(end - w, 0x400)]
        print(f"   0x{w:08x} rva 0x{w - windows.base:x} score {points} size~{end - w}")
        print(f"      strings: {sorted(wstrings[w])[:6]}")
        print(f"      head   : {head(code, w)}")
    print()
