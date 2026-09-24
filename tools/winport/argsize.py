#!/usr/bin/env python3
"""Check a structural match against the arguments its Linux symbol names.

A member function on Windows is __thiscall: it pops its own stack arguments
and ends `ret N`. The Itanium symbol spells every parameter, so N can be read
off the Linux name before looking at the DLL: `_ZN9CTFPlayer23GetEntityForLoadoutSlotEib`
is (int, bool) and has to end `ret 8`. A Windows candidate that ends `ret 8`
has passed a test the call-graph match never applied, one that knows nothing
about call graphs or field offsets.

emitgamedata.py leaves a structural match out unless its field offsets agree
(FIELDS_MIN). This gives such a match a second way in: an expected pop of at
least 4 bytes, met exactly. `ret` alone proves nothing, since every free
function and every member without arguments ends that way, so an expected 0
admits nothing.

    argsize.py server.dll matches.json

Adds "pop" and "expect" to each structural entry of matches.json in place, and
prints how often the test holds on the string and vtable matches, which are
the ones known to be right, against the same matches shuffled, which are not.
The distance between the two is what the test is worth.
"""

import collections
import json
import random
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import capstone  # noqa: E402
import matchfuncs as mf  # noqa: E402
from retcheck import first_return  # noqa: E402

STRUCTURAL = ("call", "consensus", "table")
KNOWN = ("string", "vtable")

# Parameter types passed by value whose size is not a pointer's. Anything else
# by value that is not a builtin is unknown, and the symbol gets no expectation.
SIZES = {
    "double": 8, "long long": 8, "unsigned long long": 8,
    "Vector": 12, "QAngle": 12, "Vector2D": 8, "RadianEuler": 12,
    "string_t": 4, "color32": 4, "Color": 4, "CBaseHandle": 4,
}
FOUR = {
    "bool", "char", "signed char", "unsigned char", "short", "unsigned short",
    "int", "unsigned int", "long", "unsigned long", "float", "wchar_t",
}


def split_params(text):
    out, depth, current = [], 0, ""
    for ch in text:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        out.append(current.strip())
    return out


def expected_pop(mangled, demangled):
    """Bytes a __thiscall body pops for this symbol, or None when the symbol
    is not a member (no N in its name), is variadic, or passes something by
    value whose size is not known here."""
    if not mangled.startswith("_ZN") or not demangled.endswith(")") and not demangled.endswith(") const"):
        return None
    body = demangled[:-len(" const")] if demangled.endswith(" const") else demangled
    depth = 0
    for i in range(len(body) - 1, -1, -1):
        depth += body[i] == ")"
        depth -= body[i] == "("
        if depth == 0:
            params = split_params(body[i + 1:-1])
            break
    else:
        return None
    total = 0
    for p in params:
        p = re.sub(r"\bconst\b|\bvolatile\b", "", p).strip()
        if p in ("", "void"):
            continue
        if p == "...":
            return None
        if p.endswith(("*", "&")) or re.search(r"\(\*\)|\(&\)", p) or p.startswith("CHandle<"):
            total += 4
        elif p in FOUR:
            total += 4
        elif p in SIZES:
            total += SIZES[p]
        else:
            return None
    return total


def demangle(names):
    result = subprocess.run(["c++filt"], input="\n".join(names), capture_output=True, text=True, check=True)
    return dict(zip(names, result.stdout.splitlines()))


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    windows = mf.Windows(sys.argv[1])
    matches = json.load(open(sys.argv[2]))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    plain = demangle(sorted(matches))

    def pop(entry):
        return first_return(windows, decoder, entry["rva"] + windows.base)

    for name, entry in matches.items():
        if entry.get("via") in STRUCTURAL:
            entry["expect"] = expected_pop(name, plain.get(name, ""))
            entry["pop"] = pop(entry)

    known = [(n, e) for n, e in matches.items() if e.get("via") in KNOWN and (expected_pop(n, plain.get(n, "")) or 0) >= 4]
    held = sum(1 for n, e in known if pop(e) == expected_pop(n, plain[n]))
    shuffled = [e for _, e in known]
    random.Random(1).shuffle(shuffled)
    chance = sum(1 for (n, _), e in zip(known, shuffled) if pop(e) == expected_pop(n, plain[n]))
    print(f"known matches with an expected pop of 4 or more: {len(known)}; the test holds on {held}, and on {chance} shuffled")
    by = collections.defaultdict(lambda: [0, 0, 0])
    for (n, e), other in zip(known, shuffled):
        row = by[expected_pop(n, plain[n])]
        row[0] += 1
        row[1] += pop(e) == expected_pop(n, plain[n])
        row[2] += pop(other) == expected_pop(n, plain[n])
    for expect, (count, ok, wrong) in sorted(by.items()):
        print(f"  expect {expect:3}: {count:5} known, holds on {ok}, on {wrong} shuffled")

    structural = [e for e in matches.values() if e.get("via") in STRUCTURAL]
    passed = sum(1 for e in structural if (e["expect"] or 0) >= 4 and e["pop"] == e["expect"])
    failed = sum(1 for e in structural if (e["expect"] or 0) >= 4 and e["pop"] != e["expect"])
    print(f"structural matches: {len(structural)}; pop as expected {passed}, not as expected {failed}, no expectation {len(structural) - passed - failed}")
    by = collections.defaultdict(lambda: [0, 0])
    for e in structural:
        if (e["expect"] or 0) >= 4:
            by[(e["via"], e["expect"])][0] += 1
            by[(e["via"], e["expect"])][1] += e["pop"] == e["expect"]
    for (via, expect), (count, ok) in sorted(by.items()):
        print(f"  {via:9} expect {expect:3}: {count:5}, pop as expected {ok}")
    json.dump(matches, open(sys.argv[2], "w"), indent=1)


if __name__ == "__main__":
    main()
