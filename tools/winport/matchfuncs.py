#!/usr/bin/env python3
"""Find Linux server_srv.so functions in a stripped Windows server.dll.

matchvtables.py covers virtual functions, which a vtable slot locates on both
sides. Everything else has no name on Windows, and this recovers names the way
someone reversing by hand would, only for every function at once.

Phase 1, strings. A function that is alone in referencing a string literal on
Linux, and whose Windows counterpart is alone in referencing the same literal,
is the same function. Both conditions matter: a string two functions use, or
that inlining pulled into a caller on one side, says nothing on its own.

Phase 2, calls. A matched pair calls functions in the same order on both sides,
save for inlining. Between two calls both sides already agree on, a stretch
with one unmatched call on each side names that call.

Both binaries have to come from the same game build.

    matchfuncs.py server_srv.so server.dll out.json [linux-vtables/ win-vtables/]

Needs capstone, pefile and pyelftools.
"""

import bisect
import collections
import json
import struct
import sys

import capstone
import pefile
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

MIN_STRING = 6


def c_string(data, offset):
    end = data.find(b"\0", offset)
    if end < 0 or end - offset < MIN_STRING:
        return None
    raw = data[offset:end]
    if any(b < 0x20 or b > 0x7E for b in raw if b not in (9, 10, 13)):
        return None
    return raw.decode("ascii")


class Linux:
    def __init__(self, path):
        self.file = open(path, "rb")
        self.elf = ELFFile(self.file)
        self.text = self.elf.get_section_by_name(".text")
        self.rodata = self.elf.get_section_by_name(".rodata")
        self.rodata_bytes = self.rodata.data()

        self.functions = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC" or symbol["st_value"] == 0:
                    continue
                if symbol["st_shndx"] == "SHN_UNDEF":
                    continue
                self.functions.setdefault(symbol["st_value"], (symbol.name, symbol["st_size"]))
        self.starts = sorted(self.functions)
        self.by_name = {name: addr for addr, (name, _) in self.functions.items()}
        self.text_bytes = self.text.data()

    def string_at(self, addr):
        offset = addr - self.rodata["sh_addr"]
        if 0 <= offset < len(self.rodata_bytes):
            if offset > 0 and self.rodata_bytes[offset - 1] != 0:
                return None
            return c_string(self.rodata_bytes, offset)
        return None

    def relocation_sites(self):
        """Every place in .text the loader writes an absolute address into.

        server_srv.so is not position independent: code names data by absolute
        address and the dynamic loader patches each one, so the relocation
        table lists every reference to a string, exactly as .reloc does in the
        DLL. R_386_RELATIVE and R_386_32 are those; the rest are calls."""
        base, end = self.text["sh_addr"], self.text["sh_addr"] + self.text["sh_size"]
        sites = []
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            for reloc in section.iter_relocations():
                if reloc["r_info_type"] in (8, 1) and base <= reloc["r_offset"] < end:
                    sites.append(reloc["r_offset"])
        return sorted(sites)

    def function_of(self, addr):
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return None
        start = self.starts[i]
        return start if addr < start + max(self.functions[start][1], 1) else None

    def string_references(self):
        base = self.text["sh_addr"]
        refs = collections.defaultdict(set)
        for site in self.relocation_sites():
            value = struct.unpack_from("<I", self.text_bytes, site - base)[0]
            text = self.string_at(value)
            if text is None:
                continue
            function = self.function_of(site)
            if function is not None:
                refs[text].add(function)
        return refs


class Windows:
    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=False)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = {s.Name.rstrip(b"\0").decode(): s for s in self.pe.sections}
        text = self.sections[".text"]
        self.text_start = self.base + text.VirtualAddress
        self.text_bytes = text.get_data()
        self.text_end = self.text_start + len(self.text_bytes)
        rdata = self.sections[".rdata"]
        self.rdata_start = self.base + rdata.VirtualAddress
        self.rdata_bytes = rdata.get_data()

        self.relocs = []
        for block in getattr(self.pe, "DIRECTORY_ENTRY_BASERELOC", []):
            for entry in block.entries:
                if entry.type == pefile.RELOCATION_TYPE["IMAGE_REL_BASED_HIGHLOW"]:
                    self.relocs.append(self.base + entry.rva)
        self.relocs.sort()
        self.starts = self.function_starts()

    def in_text(self, addr):
        return self.text_start <= addr < self.text_end

    def read_u32(self, addr):
        if self.in_text(addr):
            return struct.unpack_from("<I", self.text_bytes, addr - self.text_start)[0]
        offset = addr - self.rdata_start
        if 0 <= offset <= len(self.rdata_bytes) - 4:
            return struct.unpack_from("<I", self.rdata_bytes, offset)[0]
        data = self.pe.get_data(addr - self.base, 4)
        return struct.unpack("<I", data)[0]

    def function_starts(self):
        """Every address something calls or points at, inside .text, that
        follows the int3 padding MSVC aligns functions with or a ret.

        Without the padding test a stray E8 byte inside an instruction, or an
        exception funclet the unwind tables point at, starts a function in the
        middle of another, and every string after it is credited to the wrong
        one. Measured on the vtable-derived addresses, 93% of real starts
        follow CC and most of the rest follow C3."""
        starts = set()
        data = self.text_bytes
        at = data.find(b"\xe8")
        while at >= 0 and at + 5 <= len(data):
            target = (self.text_start + at + 5 + struct.unpack_from("<i", data, at + 1)[0]) & 0xFFFFFFFF
            if self.in_text(target):
                starts.add(target)
            at = data.find(b"\xe8", at + 1)
        for site in self.relocs:
            try:
                value = self.read_u32(site)
            except Exception:
                continue
            if self.in_text(value) and not self.in_text(site):
                starts.add(value)
        data = self.text_bytes
        return sorted(a for a in starts if a > self.text_start and data[a - self.text_start - 1] in (0xCC, 0xC3))

    def function_of(self, addr):
        i = bisect.bisect_right(self.starts, addr) - 1
        return self.starts[i] if i >= 0 else None

    def string_at(self, addr):
        offset = addr - self.rdata_start
        if 0 <= offset < len(self.rdata_bytes):
            if offset > 0 and self.rdata_bytes[offset - 1] != 0:
                return None
            return c_string(self.rdata_bytes, offset)
        return None

    def string_references(self):
        refs = collections.defaultdict(set)
        for site in self.relocs:
            if not self.in_text(site):
                continue
            text = self.string_at(self.read_u32(site))
            if text is not None:
                refs[text].add(self.function_of(site))
        return refs


def call_targets(cs, code, address, known_starts, in_text=None):
    """Direct call targets, and tail jumps to a known function start, in order.

    A call decoded inside a function already matched is trusted to land on a
    function even when padding does not say so; a jmp is only a tail call when
    it lands on a known start, since most jumps stay inside the function."""
    out = []
    for insn in cs.disasm(code, address):
        if not insn.operands or insn.operands[0].type != capstone.x86.X86_OP_IMM:
            continue
        target = insn.operands[0].imm & 0xFFFFFFFF
        if target == address:
            continue
        if insn.mnemonic == "call" and (target in known_starts or (in_text is not None and in_text(target))):
            out.append(target)
        elif insn.mnemonic == "jmp" and target in known_starts:
            out.append(target)
    return out


def lcs(a, b):
    """Longest common subsequence of two short lists, as index pairs."""
    n, m = len(a), len(b)
    table = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            table[i][j] = table[i + 1][j + 1] + 1 if a[i] == b[j] else max(table[i + 1][j], table[i][j + 1])
    pairs, i, j = [], 0, 0
    while i < n and j < m:
        if a[i] == b[j]:
            pairs.append((i, j))
            i, j = i + 1, j + 1
        elif table[i + 1][j] >= table[i][j + 1]:
            i += 1
        else:
            j += 1
    return pairs


def propagate(linux, windows, seeds, rounds=30, ordered=0):
    """Phase 2: name unmatched callees between calls both sides agree on.

    seeds maps a Linux function address to a Windows one. Returns the pairs it
    added, each with the pair whose body gave it away."""
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    linux_starts = set(linux.functions)
    windows_starts = set(windows.starts)
    lbase = linux.text["sh_addr"]
    calls_linux, calls_windows = {}, {}

    def linux_calls(addr):
        if addr not in calls_linux:
            size = linux.functions[addr][1]
            calls_linux[addr] = call_targets(cs, linux.text_bytes[addr - lbase:addr - lbase + size], addr, linux_starts)
        return calls_linux[addr]

    def windows_calls(addr):
        if addr not in calls_windows:
            i = bisect.bisect_right(windows.starts, addr)
            end = windows.starts[i] if i < len(windows.starts) else windows.text_end
            end = min(end, addr + 0x4000)
            off = addr - windows.text_start
            calls_windows[addr] = call_targets(cs, windows.text_bytes[off:off + (end - addr)], addr, windows_starts, windows.in_text)
        return calls_windows[addr]

    forward = dict(seeds)
    backward = {w: l for l, w in forward.items()}
    added = {}
    for round_number in range(rounds):
        proposals = collections.defaultdict(set)
        evidence = {}
        for l, w in list(forward.items()):
            lseq, wseq = linux_calls(l), windows_calls(w)
            if not lseq or not wseq:
                continue
            la = [(i, forward[t]) for i, t in enumerate(lseq) if t in forward]
            wa = [(j, t) for j, t in enumerate(wseq) if t in backward]
            common = lcs([x[1] for x in la], [x[1] for x in wa])
            bounds = [(-1, -1)] + [(la[i][0], wa[j][0]) for i, j in common] + [(len(lseq), len(wseq))]
            for (l0, w0), (l1, w1) in zip(bounds, bounds[1:]):
                lu = [t for t in lseq[l0 + 1:l1] if t not in forward]
                wu = [t for t in wseq[w0 + 1:w1] if t not in backward]
                if len(set(lu)) == 1 and len(set(wu)) == 1:
                    pairs = [(lu[0], wu[0])]
                elif ordered and 1 < len(lu) == len(wu) <= ordered:
                    # Same number of unmatched call sites on each side: pair
                    # them in order. Conflicting proposals are dropped below.
                    pairs = list(zip(lu, wu))
                else:
                    pairs = []
                for lt, wt in pairs:
                    proposals[lt].add(wt)
                    evidence[(lt, wt)] = l
        claimed = collections.Counter()
        for lt, ws in proposals.items():
            if len(ws) == 1:
                claimed[next(iter(ws))] += 1
        new = 0
        for lt, ws in proposals.items():
            if len(ws) != 1:
                continue
            wt = next(iter(ws))
            if wt in backward or claimed[wt] > 1:
                continue
            forward[lt] = wt
            backward[wt] = lt
            added[lt] = (wt, evidence[(lt, wt)])
            new += 1
        print(f"calls round {round_number + 1}: {new} new")
        if new == 0:
            break
    return added


def vtable_pairs(linux_dir, windows_dir):
    """Linux address -> Windows address, from every class whose primary vtables
    align (see matchvtables.py).

    A base class's function sits in many derived vtables, so one pair is
    usually claimed by many classes. A pair is kept only when every class that
    claims it agrees and it is one-to-one: a misaligned class contradicts the
    classes that aligned, and MSVC folding identical small functions into one
    address makes a Windows address stand for several Linux ones. Destructors
    and pure virtual stubs are left out, since the two ABIs model them
    differently."""
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    import matchvtables as mv

    claims = collections.defaultdict(set)
    for linux_path in Path(linux_dir).glob("*.txt"):
        win_path = Path(windows_dir) / linux_path.name
        if not win_path.exists():
            continue
        windows = mv.read_windows(win_path).get(0)
        if not windows:
            continue
        rows, offset = [], 0
        for line in linux_path.read_text(errors="replace").splitlines():
            line = line.strip()
            header = mv.LINUX_HEADER.match(line)
            if header:
                offset = int(header.group(1), 16)
                continue
            m = mv.LINUX_LINE.match(line)
            if m and offset == 0:
                parts = line.split(None, 2)
                if len(parts) == 3:
                    rows.append((parts[2].strip(), int(parts[1], 16)))
        signatures = [sig for sig, _ in rows]
        how, aligned = mv.align(signatures, windows)
        if aligned is None or how not in ("raw", "collapse"):
            continue
        address_of = {}
        for sig, addr in rows:
            address_of.setdefault(sig, addr)
        for sig, win in zip(aligned, windows):
            name = mv.bare_name(sig).split("::")[-1]
            if name.startswith("~") or "pure_virtual" in sig:
                continue
            claims[address_of[sig]].add(win)

    forward = {l: next(iter(ws)) for l, ws in claims.items() if len(ws) == 1}
    reverse = collections.Counter(forward.values())
    return {l: w for l, w in forward.items() if reverse[w] == 1}


def main():
    linux_path, windows_path, out_path = sys.argv[1:4]
    linux = Linux(linux_path)
    windows = Windows(windows_path)
    print(f"linux: {len(linux.functions)} functions; windows: {len(windows.starts)} function starts, {len(windows.relocs)} relocations")

    win_refs = windows.string_references()
    print(f"windows: {len(win_refs)} strings referenced from code")

    linux_refs = linux.string_references()
    print(f"linux: {len(linux_refs)} strings referenced from code")

    matches = {}
    conflicts = set()
    for text, lin in linux_refs.items():
        win = win_refs.get(text)
        if len(lin) != 1 or not win or len(win) != 1:
            continue
        (l,), (w,) = tuple(lin), tuple(win)
        name = linux.functions[l][0]
        if name in matches and matches[name]["windows"] != w:
            conflicts.add(name)
            continue
        entry = matches.setdefault(name, {"windows": w, "strings": []})
        entry["strings"].append(text)
    for name in conflicts:
        matches.pop(name, None)

    windows_taken = collections.Counter(m["windows"] for m in matches.values())
    for name in [n for n, m in matches.items() if windows_taken[m["windows"]] > 1]:
        matches.pop(name)

    # Every string each side's function references, to say how alike the two
    # are beyond the one string that paired them. Inlining moves strings into
    # callers, so a low overlap is where a pairing is least trustworthy.
    linux_sets, windows_sets = collections.defaultdict(set), collections.defaultdict(set)
    for text, functions in linux_refs.items():
        for f in functions:
            linux_sets[f].add(text)
    for text, functions in win_refs.items():
        for f in functions:
            windows_sets[f].add(text)

    result = {}
    for name, m in sorted(matches.items()):
        l, w = linux_sets[linux.by_name[name]], windows_sets[m["windows"]]
        result[name] = {
            "rva": m["windows"] - windows.base,
            "via": "string",
            "overlap": round(len(l & w) / len(l | w), 3),
            "evidence": m["strings"][:3],
        }
    print(f"matched by unique string: {len(result)}; dropped for disagreement: {len(conflicts)}")

    seeds = {linux.by_name[name]: m["windows"] for name, m in matches.items()}
    if len(sys.argv) > 5:
        vt = vtable_pairs(sys.argv[4], sys.argv[5])
        disagree = sum(1 for l, w in vt.items() if l in seeds and seeds[l] != w)
        agree = sum(1 for l, w in vt.items() if l in seeds and seeds[l] == w)
        print(f"vtable pairs: {len(vt)}; against string matches: {agree} agree, {disagree} disagree")
        taken = set(seeds.values())
        for l, w in vt.items():
            name = linux.functions.get(l, (None,))[0]
            if name is None or l in seeds or w in taken:
                continue
            seeds[l] = w
            taken.add(w)
            result[name] = {"rva": w - windows.base, "via": "vtable", "evidence": []}
    for l, (w, via) in propagate(linux, windows, seeds).items():
        result[linux.functions[l][0]] = {
            "rva": w - windows.base,
            "via": "call",
            "evidence": [linux.functions[via][0]],
        }
    print(f"matched in total: {len(result)}")
    json.dump(result, open(out_path, "w"), indent=1)


if __name__ == "__main__":
    main()
