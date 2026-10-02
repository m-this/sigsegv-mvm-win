#!/usr/bin/env python3
"""Carry addresses verified on one build of a Windows binary to another build.

overrides.json and knownvtidx.generated.txt hold RVAs read off one build of
server.dll. A Valve update moves almost every function, so those RVAs point
into the middle of something else on the next build, and the extension calls
it. This finds each one again.

A function is found by its own bytes: everything from its start to the next
function start, with the operands that move between builds wildcarded (every
base relocation, and the rel32 of every call and jump). The masked body has to
match exactly once in the new .text, whole; a body too short or not unique
takes the bytes after it as context. A function whose body changed is not
carried: a gap fails out loud, a guess does not.

A global is found through the functions that reference it: each reference
site inside a function that was carried is read at the same offset in the new
build, and every one of them has to agree.

    rebase.py OLD.dll NEW.dll RVA...
    rebase.py OLD.dll NEW.dll --json in.json    # in.json is a list of RVAs

The result is JSON on stdout, {"0xOLD": "0xNEW" or null}, and the evidence for
each on stderr.
"""

import json
import re
import sys
from bisect import bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import capstone  # noqa: E402
import matchfuncs as mf  # noqa: E402

BODY_BYTES_MAX = 4096
CONTEXT_BYTES_MAX = 1024
KEPT_BYTES_MIN = 12


class Image:
    def __init__(self, path):
        self.w = mf.Windows(path)
        self.reloc_set = set(self.w.relocs)
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    def masked(self, va, end):
        """Bytes from va to end, and which of them must match."""
        w = self.w
        raw = w.text_bytes[va - w.text_start:end - w.text_start]
        keep = bytearray(b"\x01" * len(raw))
        for at in range(len(raw)):
            if va + at in self.reloc_set:
                keep[at:at + 4] = b"\x00\x00\x00\x00"
        for insn in self.cs.disasm(raw, va):
            b = insn.bytes
            if b[0] in (0xE8, 0xE9) or (len(b) >= 6 and b[0] == 0x0F and 0x80 <= b[1] <= 0x8F):
                off = insn.address - va + len(b) - 4
                keep[off:off + 4] = b"\x00\x00\x00\x00"
        return raw, bytes(keep[:len(raw)])

    def body_end(self, va):
        """The next function start, or BODY_BYTES_MAX on, without trailing int3s."""
        w = self.w
        index = bisect_right(w.starts, va)
        end = w.starts[index] if index < len(w.starts) else w.text_end
        end = min(end, va + BODY_BYTES_MAX, w.text_end)
        while end > va and w.text_bytes[end - 1 - w.text_start] == 0xCC:
            end -= 1
        return end

    def find(self, raw, keep, limit=2):
        pattern = b"".join(re.escape(bytes([c])) if k else b"." for c, k in zip(raw, keep))
        rx = re.compile(pattern, re.DOTALL)
        hits = []
        for m in rx.finditer(self.w.text_bytes):
            hits.append(self.w.text_start + m.start())
            if len(hits) >= limit:
                break
        return hits


def carry_function(old, new, va):
    """The new address of the function at va, and how many bytes vouch for it.

    The whole body has to match. A body that is too short or not unique in the
    old build (entity factories differ only in a relocated vtable pointer) takes
    the bytes after it as context, up to CONTEXT_BYTES_MAX: link order holds
    between builds, and if the neighbour changed the match fails, it does not
    land elsewhere."""
    end = old.body_end(va)
    stop = min(va + CONTEXT_BYTES_MAX, old.w.text_end)
    while True:
        raw, keep = old.masked(va, end)
        if sum(keep) >= KEPT_BYTES_MIN and old.find(raw, keep) == [va]:
            break
        if end >= stop:
            return None, "not unique in the old build"
        end = min(max(end + 16, va + KEPT_BYTES_MIN), stop)
    hits = new.find(raw, keep)
    if len(hits) != 1:
        return None, f"{len(hits)} matches in the new build"
    for at in range(len(raw)):
        if va + at in old.reloc_set:
            text = old.w.string_at(old.w.read_u32(va + at))
            if text is not None and text != new.w.string_at(new.w.read_u32(hits[0] + at)):
                return None, f"names another string than {text!r}"
    return hits[0], f"{len(raw)} bytes"


def carry_global(old, new, va, carry):
    """Votes from every reference site in a function that carries."""
    votes = {}
    for site in old.referrers.get(va, ()):
        fn = old.w.function_of(site)
        got = fn is not None and carry(fn)
        if not got or site + 4 > old.body_end(fn):
            continue
        new_site = got + (site - fn)
        if new_site not in new.reloc_set:
            return None, f"site {site:#x} has no relocation in the new build"
        value = new.w.read_u32(new_site)
        votes[value] = votes.get(value, 0) + 1
    if len(votes) != 1:
        return None, f"{len(votes)} distinct values from the reference sites"
    (value, count), = votes.items()
    return value, f"{count} reference sites agree"


def rebase(old_path, new_path, rvas):
    old, new = Image(old_path), Image(new_path)
    old.referrers = {}
    for site in old.w.relocs:
        if old.w.in_text(site):
            old.referrers.setdefault(old.w.read_u32(site), []).append(site)
    cache = {}

    def carry(va):
        if va not in cache:
            cache[va] = carry_function(old, new, va)
        return cache[va][0]

    out, why = {}, {}
    for rva in rvas:
        va = rva + old.w.base
        if old.w.in_text(va):
            carry(va)
            got, reason = cache[va]
        else:
            got, reason = carry_global(old, new, va, carry)
        out[rva], why[rva] = (got - new.w.base if got else None), reason
    return out, why


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    if sys.argv[3] == "--json":
        rvas = [int(x, 16) if isinstance(x, str) else x for x in json.load(open(sys.argv[4]))]
    else:
        rvas = [int(x, 16) for x in sys.argv[3:]]
    out, why = rebase(sys.argv[1], sys.argv[2], rvas)
    for rva in rvas:
        got = out[rva]
        print(f"{rva:#x} -> {got:#x}" if got is not None else f"{rva:#x} -> none", why[rva], file=sys.stderr)
    json.dump({f"{k:#x}": (f"{v:#x}" if v is not None else None) for k, v in out.items()}, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
