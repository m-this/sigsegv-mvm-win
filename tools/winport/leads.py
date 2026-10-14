#!/usr/bin/env python3
"""For an address with no match, say what there is to go on.

matchfuncs.py pairs a function when it is alone in referencing a string on
both sides. 1,195 of the addresses that fail on Windows never met that bar,
and "no match" hides three very different situations:

  a few candidates   the Linux function's strings are referenced by two or
                     three Windows functions. Reading three disassemblies is
                     an afternoon, not a research project, and the answer goes
                     in overrides.json.
  nothing shared     no Windows function references any of its strings. The
                     function was inlined away, or it has no strings, and the
                     route is a call site or a hand signature.
  no strings at all  the Linux function references none, so this says nothing
                     either way.

    leads.py server_srv.so server.dll matches.json wanted.json [--mod NAME]

wanted.json is a list of [name, symbol, ...] rows, as gated.json and
unmatched.json carry. Prints the narrowest leads first, which is the order to
work them in.
"""

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import matchfuncs as mf  # noqa: E402

MAX_CANDIDATES = 6


def main():
    if len(sys.argv) < 5:
        sys.exit(__doc__)
    linux = mf.Linux(sys.argv[1])
    windows = mf.Windows(sys.argv[2])
    matches = json.load(open(sys.argv[3]))
    wanted = json.load(open(sys.argv[4]))

    taken = {match["rva"] + windows.base for match in matches.values()}

    linux_strings = {}
    for text, functions in linux.string_references().items():
        for function in functions:
            linux_strings.setdefault(function, set()).add(text)
    windows_by_string = collections.defaultdict(set)
    for text, functions in windows.string_references().items():
        windows_by_string[text] |= set(functions)

    rows = []
    for row in wanted:
        name, symbol = row[0], row[1]
        address = linux.by_name.get(symbol)
        if address is None:
            continue
        strings = linux_strings.get(address, set())
        if not strings:
            rows.append((name, symbol, None, set(), set()))
            continue
        # Intersect the candidate sets: a function referencing all of them is a
        # far narrower claim than one referencing any.
        candidates = None
        for text in strings:
            here = windows_by_string.get(text, set())
            candidates = here if candidates is None else (candidates & here)
        candidates = candidates or set()
        rows.append((name, symbol, len(strings), candidates, candidates - taken))

    buckets = collections.Counter()
    workable = []
    for name, symbol, n_strings, candidates, free in rows:
        if n_strings is None:
            buckets["the Linux function references no string"] += 1
        elif not candidates:
            buckets["no Windows function references them all"] += 1
        elif len(free) == 1:
            buckets["exactly one unclaimed candidate"] += 1
            workable.append((len(free), name, n_strings, free))
        elif 1 < len(free) <= MAX_CANDIDATES:
            buckets[f"2 to {MAX_CANDIDATES} unclaimed candidates"] += 1
            workable.append((len(free), name, n_strings, free))
        elif not free:
            buckets["every candidate is already claimed"] += 1
        else:
            buckets["too many candidates to read"] += 1

    for key, n in buckets.most_common():
        print(f"{n:5}  {key}")
    print(f"\nleads worth reading, narrowest first ({len(workable)}):")
    for count, name, n_strings, free in sorted(workable):
        addresses = " ".join(f"0x{a - windows.base:x}" for a in sorted(free)[:MAX_CANDIDATES])
        print(f"  {count} candidate(s)  {name[:50]:50} from {n_strings} string(s): {addresses}")


if __name__ == "__main__":
    main()
