#!/usr/bin/env python3
"""Find functions whose body changed between two builds of a Windows DLL.

    fuzzy.py OLD.dll NEW.dll RVA...

Anchors are functions whose masked body is unique and identical in both builds.
Link order holds, so a changed function lies between the new images of its
nearest anchors. Candidates there are scored on referenced strings, anchored
callees and mnemonic similarity. JSON on stdout: {"0xOLD": {"new", "score",
"runner_up", "window", "evidence"}}.
"""

import difflib
import hashlib
import json
import sys
from bisect import bisect_left, bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import rebase  # noqa: E402

WINDOW_FUNCS_MAX = 400


def bodies(img):
    out = {}
    w = img.w
    for i, va in enumerate(w.starts):
        if not w.in_text(va):
            continue
        end = img.body_end(va)
        if end - va < 16:
            continue
        raw, keep = img.masked(va, end)
        h = hashlib.sha1(bytes(c if k else 0 for c, k in zip(raw, keep))).digest()
        out.setdefault(h, []).append(va)
    return out


def anchors(old, new):
    bo, bn = bodies(old), bodies(new)
    pairs = {}
    for h, olds in bo.items():
        news = bn.get(h)
        if len(olds) == 1 and news and len(news) == 1:
            pairs[olds[0]] = news[0]
    return pairs


def features(img, va):
    w = img.w
    end = img.body_end(va)
    raw = w.text_bytes[va - w.text_start:end - w.text_start]
    mnems, strings, calls = [], set(), []
    for insn in img.cs.disasm(raw, va):
        mnems.append(insn.mnemonic)
        b = insn.bytes
        if b[0] == 0xE8 and len(b) == 5:
            calls.append(insn.address + 5 + int.from_bytes(b[1:], "little", signed=True))
    for at in range(len(raw)):
        if va + at in img.reloc_set:
            s = w.string_at(w.read_u32(va + at))
            if s:
                strings.add(s)
    return {"mnems": mnems, "strings": strings, "calls": calls, "size": end - va}


def score(fo, fn, amap):
    s = 0.0
    if fo["strings"] or fn["strings"]:
        inter = len(fo["strings"] & fn["strings"])
        s += 4.0 * inter / max(len(fo["strings"] | fn["strings"]), 1)
    mapped = [amap.get(c) for c in fo["calls"]]
    known = [m for m in mapped if m]
    if known:
        s += 3.0 * sum(1 for m in known if m in fn["calls"]) / len(known)
    s += 3.0 * difflib.SequenceMatcher(None, fo["mnems"], fn["mnems"], autojunk=False).ratio()
    return s


def align(old, new, olds, news, amap, target):
    fo = [features(old, o) for o in olds]
    fn = [features(new, n) for n in news]
    sc = [[score(a, b, amap) for b in fn] for a in fo]
    n, m = len(olds), len(news)
    dp = [[0.0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            take = sc[i][j] + dp[i + 1][j + 1] if sc[i][j] >= 2.0 else -1
            dp[i][j] = max(take, dp[i + 1][j], dp[i][j + 1])
    i = j = 0
    while i < n and j < m:
        if sc[i][j] >= 2.0 and dp[i][j] == sc[i][j] + dp[i + 1][j + 1]:
            if olds[i] == target:
                return news[j], sc[i][j]
            i, j = i + 1, j + 1
        elif dp[i][j] == dp[i + 1][j]:
            if olds[i] == target:
                return None, 0.0
            i += 1
        else:
            j += 1
    return None, 0.0


def main():
    old, new = rebase.Image(sys.argv[1]), rebase.Image(sys.argv[2])
    amap = anchors(old, new)
    keys = sorted(amap)
    print(f"{len(amap)} anchors", file=sys.stderr)
    out = {}
    for arg in sys.argv[3:]:
        va = int(arg, 16) + old.w.base
        i = bisect_left(keys, va)
        lo_old = keys[i - 1] if i > 0 else None
        hi_old = keys[i] if i < len(keys) and keys[i] != va else (keys[i + 1] if i + 1 < len(keys) else None)
        lo, hi = amap.get(lo_old, new.w.text_start), amap.get(hi_old, new.w.text_end)
        if hi <= lo:
            out[arg] = {"new": None, "evidence": "anchors out of order"}
            continue
        cands = new.w.starts[bisect_right(new.w.starts, lo):bisect_left(new.w.starts, hi)]
        rank_old = bisect_left(old.w.starts, va) - bisect_left(old.w.starts, lo_old or old.w.text_start)
        if len(cands) > WINDOW_FUNCS_MAX:
            out[arg] = {"new": None, "evidence": f"window of {len(cands)} functions"}
            continue
        fo = features(old, va)
        olds = old.w.starts[bisect_right(old.w.starts, lo_old or old.w.text_start):bisect_left(old.w.starts, hi_old or old.w.text_end)]
        olds = [o for o in olds if old.w.in_text(o)]
        pick, pair_score = align(old, new, olds, cands, amap, va)
        ranked = sorted(((score(fo, features(new, c), amap), c) for c in cands), reverse=True)
        best = (pair_score, pick)
        second = next(((sc, c) for sc, c in ranked if c != pick), (0, None))
        fb = features(new, best[1]) if best[1] else None
        out[arg] = {
            "new": hex(best[1] - new.w.base) if best[1] else None,
            "score": round(best[0], 3),
            "runner_up": round(second[0], 3),
            "window": len(cands),
            "rank_old_in_window": rank_old,
            "rank_new_in_window": cands.index(best[1]) + 1 if best[1] else None,
            "size_old_new": [fo["size"], fb["size"] if fb else None],
            "strings_old": sorted(fo["strings"])[:4],
        }
    json.dump(out, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
