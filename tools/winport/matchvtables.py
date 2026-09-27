"""Align a Linux vtable against its Windows twin and emit `func knownvtidx`.

Both vtables are generated from the same class definition, so their slots are
the same functions in almost the same order. Only the Linux side carries names.
Turning a Linux slot into a Windows index is therefore an alignment problem, and
the two ABIs differ in exactly two ways that matter here:

  * Destructors. The Itanium ABI emits two slots, the complete object destructor
    and the deleting destructor, and they appear in the dump as the same
    signature twice in a row. MSVC emits one, the vector deleting destructor.
  * Overloads. MSVC lays out a class's own new virtuals by name: all of one
    name sit together, at the place the class first declares that name, and
    in reverse declaration order among themselves. Itanium keeps declaration
    order. So CBaseEntity's three KeyValue overloads are reversed, and
    CGameMovement's GetPlayerMins(), declared long after the GetPlayerMins(bool)
    it overrides, moves up to where that override is declared.

The destructor rule is a question of length, so this tries raw and then
collapsed and keeps the one that makes the two tables the same length. The
overload rule never changes a length, so no length can tell whether it applies;
it is applied always. It needs to know which slots are the class's own new
virtuals, and the dumps do not say, so the class's primary base is taken to be
the longest other Linux table its own table starts with, name for name (see
Corpus). Equal length is evidence, not proof: it is strong for a class with one
vtable and worth nothing for one with several, which is why a class MSVC gave
more than one vtable is refused outright.

Everything else is refused too. A wrong vtable index is a call into the wrong
function, which is a crash at best and silent corruption at worst, and a gap
somebody fills by hand is much cheaper than that.

    python3 matchvtables.py <linux-dump-dir> <windows-dump-dir> <classified.json>
"""
import json, re, sys
from collections import defaultdict
from pathlib import Path

LINUX_LINE = re.compile(r"^\+0x([0-9a-fA-F]+):\s+[0-9a-fA-F]+\s+(.*)$")
WIN_LINE = re.compile(r"^\+0x([0-9a-fA-F]+):\s+([0-9a-fA-F]+)\s*$")
LINUX_HEADER = re.compile(r"^// vtable at 0x[0-9a-fA-F]+ offset 0x([0-9a-fA-F]+)\s*$")
WIN_HEADER = re.compile(r"^// vtable at 0x[0-9a-fA-F]+ offset 0x([0-9a-fA-F]+)\s*$")


def read_linux(path):
    """The class's primary vtable: the sub-table at offset 0, as names.

    dumplinuxvtables.py writes one header per sub-table, the same way the
    Windows dump does, so a class that multiply inherits is compared table for
    table. The old hand-made dumps under mvm-reversed have no headers and are a
    flat walk that runs on into the secondary tables; for those there is
    nothing to cut on and everything read is treated as the primary table,
    which is what this tool did before.
    """
    slots, offset = [], 0
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        header = LINUX_HEADER.match(line)
        if header:
            offset = int(header.group(1), 16)
            continue
        m = LINUX_LINE.match(line)
        if m and offset == 0:
            slots.append(m.group(2).strip())
    return slots


def read_windows(path):
    """offset -> slots, for every vtable the dump holds for this class.

    A class that multiply inherits gets one table per base subobject, and the
    locator offset says which is which. The one at offset 0 is the class's own,
    holding its primary base's virtuals and then its own, which is the same
    thing the Linux dump's primary table holds. The rest belong to the bases
    and have no counterpart in a dump keyed by class name.
    """
    tables, offset = {}, None
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        header = WIN_HEADER.match(line)
        if header:
            offset = int(header.group(1), 16)
            tables.setdefault(offset, [])
            continue
        m = WIN_LINE.match(line)
        if m and offset is not None:
            tables[offset].append(int(m.group(2), 16))
    return tables


def bare_name(signature):
    """CTFPlayer::Foo(int) const -> CTFPlayer::Foo, for spotting overload runs."""
    depth, cut = 0, len(signature)
    for i in range(len(signature) - 1, -1, -1):
        c = signature[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
            if depth == 0:
                cut = i
                break
    return signature[:cut].strip()


def collapse_destructors(slots):
    """Two Itanium destructor slots become the one MSVC emits."""
    out, i = [], 0
    while i < len(slots):
        name = bare_name(slots[i])
        if (i + 1 < len(slots) and slots[i] == slots[i + 1]
                and name.split("::")[-1].startswith("~")):
            out.append(slots[i])
            i += 2
        else:
            out.append(slots[i])
            i += 1
    return out


def split_name(signature):
    """CTFPlayer::KeyValue(char const*, float) -> ("CTFPlayer", "KeyValue").

    The last `::` outside template brackets, so CUtlVector<A::B>::Foo splits
    after the `>`. An operator's name can hold brackets of its own, so it is
    cut at `::operator` first."""
    bare = bare_name(signature)
    at = bare.rfind("::operator")
    if at >= 0 and "::" not in bare[at + 2:]:
        return bare[:at], bare[at + 2:]
    depth = 0
    for i in range(len(bare) - 1, 0, -1):
        c = bare[i]
        if c == ">":
            depth += 1
        elif c == "<":
            depth -= 1
        elif depth == 0 and c == ":" and bare[i - 1] == ":":
            return bare[:i - 1], bare[i + 1:]
    return "", bare


def unnamed(signature):
    """A slot with no function of its own to name: a pure or deleted virtual."""
    return not signature or "__cxa_pure_virtual" in signature or "__cxa_deleted_virtual" in signature


def method(signature):
    """The name MSVC groups by: KeyValue for any KeyValue, `~` for a destructor."""
    name = split_name(signature)[1]
    return "~" if name.startswith("~") else name


def slot_key(signature):
    """What a slot means whichever class implements it: the name and the
    parameters without the class. A base's slot and the derived class's
    override of it have the same key. None for a slot with no name, which
    matches anything."""
    if unnamed(signature):
        return None
    name = method(signature)
    return name if name == "~" else name + signature[len(bare_name(signature)):].strip()


class Corpus:
    """Every Linux primary table, for telling a class's own new virtuals from
    the ones it inherits.

    The dumps carry no base classes, but a primary base's table is a prefix of
    the derived class's, slot for slot by name and parameters. The longest
    other table a class's own starts with is taken as its primary base, and the
    slots past it are the class's own new virtuals. A table missing from the
    dump merges two classes' runs into one, which only matters when both
    declare the same name.
    """

    def __init__(self, linux_dir):
        self.tables, self.pretty = {}, {}
        for path in sorted(Path(linux_dir).glob("*.txt")):
            slots = read_linux(path)
            if slots:
                self.tables[path.stem] = slots
                head = path.read_text(errors="replace").split("\n", 1)[0].strip()
                self.pretty[path.stem] = head if head and not head.startswith(("//", "+")) else path.stem
        self.keys = {cls: tuple(slot_key(s) for s in slots) for cls, slots in self.tables.items()}
        # A table with a pure slot matches by walking it; every other one by a
        # hash of its whole key list, looked up at each prefix of the class.
        self.wild = sorted((c for c, k in self.keys.items() if None in k),
                           key=lambda c: (-len(self.keys[c]), c))
        self.exact = defaultdict(list)
        for cls, keys in self.keys.items():
            if None not in keys:
                self.exact[(len(keys), self.prefix_hashes(keys)[-1])].append(cls)
        self._orders = {}
        # Groups moved to where the class overrides the same name, for the log:
        # the one place the rule is applied on an assumption (see order).
        self.moved = defaultdict(list)

    @staticmethod
    def prefix_hashes(keys):
        out, h = [0], 0
        for k in keys:
            h = hash((h, k))
            out.append(h)
        return out

    def parent(self, cls):
        """The longest other table this one starts with, or None."""
        keys = self.keys[cls]
        hashes = self.prefix_hashes(keys)
        best = None
        for m in range(len(keys) - 1, 0, -1):
            found = sorted(c for c in self.exact.get((m, hashes[m]), ()) if c != cls and self.keys[c] == keys[:m])
            if found:
                best = found[0]
                break
        for other in self.wild:
            theirs = self.keys[other]
            if len(theirs) >= len(keys) or (best and len(theirs) <= len(self.keys[best])):
                continue
            if all(t is None or t == k for t, k in zip(theirs, keys)):
                return other
        return best

    def order(self, cls):
        """The Linux slot indices of `cls` in the order MSVC lays them out.

        A class's own new virtuals are grouped by name. A group goes where the
        class first declares that name, which is its first new virtual of that
        name unless the class also overrides an inherited virtual of the same
        name: the override is declared somewhere the binary does not record,
        and it is taken to come before the class's new virtuals, the way
        CGameMovement declares the IGameMovement interface it implements first.
        Those classes are recorded in `moved`.
        """
        if cls in self._orders:
            return self._orders[cls]
        slots = self.tables[cls]
        base = self.parent(cls)
        inherited = list(self.order(base)) if base else []
        start = len(self.tables[base]) if base else 0
        own = self.pretty[cls]

        overrides = {}
        for j in range(start):
            if not unnamed(slots[j]):
                qualifier, name = split_name(slots[j])
                if qualifier == own:
                    overrides.setdefault(method(slots[j]), j)
        groups = {}
        for i in range(start, len(slots)):
            groups.setdefault(("#", i) if unnamed(slots[i]) else method(slots[i]), []).append(i)
        early = sorted((g for g in groups if g in overrides), key=overrides.get)
        rest = [g for g in groups if g not in overrides]
        if early and list(groups)[:len(early)] != early:
            self.moved[cls] += early
        new = [i for g in early + rest for i in reversed(groups[g])]
        self._orders[cls] = inherited + new
        return self._orders[cls]


def align(linux, windows, order=None):
    """The Linux table in MSVC's order, destructors collapsed if that is what
    makes the two agree in length, or None. `order` is Corpus.order's; without
    it the slots keep Linux order."""
    arranged = [linux[i] for i in order] if order is not None else list(linux)
    for name, candidate in (("raw", arranged), ("collapse", collapse_destructors(arranged))):
        if len(candidate) == len(windows):
            return name, candidate
    return None, None


def count_tables(path):
    return sum(1 for line in path.read_text(errors="replace").splitlines()
               if line.strip().startswith("// vtable at"))


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        raise SystemExit(2)
    linux_dir, win_dir, classified = (Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))

    wanted = defaultdict(list)
    for row in json.loads(classified.read_text())["virtual"]:
        wanted[row["class"]].append(row)

    corpus = Corpus(linux_dir)
    resolved, refused, missing, multi = [], [], [], []
    from_multi = 0
    used = defaultdict(int)
    for cls, rows in sorted(wanted.items()):
        linux_path, win_path = linux_dir / f"{cls}.txt", win_dir / f"{cls}.txt"
        if not linux_path.exists() or not win_path.exists():
            missing.append((cls, len(rows)))
            continue
        tables = read_windows(win_path)
        windows = tables.get(0)
        if windows is None:
            # Every class should have a table at offset 0. One that does not is
            # a dump this tool does not understand, and guessing which of the
            # rest is primary is exactly the guess that puts a call in the
            # wrong function.
            multi.append((cls, len(rows)))
            continue
        if len(tables) > 1:
            from_multi += len(rows)
        linux = read_linux(linux_path)
        how, aligned = align(linux, windows, corpus.order(cls))
        if aligned is None:
            refused.append((cls, len(collapse_destructors(linux)), len(windows), len(rows)))
            continue
        used[how] += 1
        index_of = {sig: i for i, sig in enumerate(aligned)}
        for row in rows:
            at = index_of.get(row["sig"])
            if at is None:
                refused.append((cls, len(aligned), len(windows), 1))
            else:
                resolved.append({**row, "win_index": at, "win_addr": windows[at], "how": how})

    total = sum(len(r) for r in wanted.values())
    print(f"virtual addresses wanted : {total} across {len(wanted)} classes")
    print(f"  resolved to an index   : {len(resolved)}")
    print(f"  no table at offset 0   : {sum(m[1] for m in multi)} in {len(multi)} classes")
    print(f"    of the resolved, from a class with several tables: {from_multi}")
    print(f"  no alignment fits      : {sum(r[3] for r in refused)} in {len(refused)} classes")
    print(f"  no dump on one side    : {sum(m[1] for m in missing)} in {len(missing)} classes")
    if used:
        print("\n  alignment used, by class:")
        for how, n in sorted(used.items(), key=lambda kv: -kv[1]):
            print(f"    {how:<18} {n}")
    if corpus.moved:
        print("\n  overload groups moved up to an override of the same name:")
        for cls, names in sorted(corpus.moved.items()):
            print(f"    {cls:<42} {' '.join(names)}")
    if refused:
        print("\n  refused, worst first (class: linux slots vs windows slots):")
        for cls, ln, wn, n in sorted(refused, key=lambda r: -r[3])[:8]:
            print(f"    {cls:<42} {ln:>4} vs {wn:<4}  costs {n}")

    out = Path("winport_knownvtidx.txt")
    with out.open("w") as fh:
        fh.write("// Generated by tools/winport/matchvtables.py. Do not hand-edit.\n")
        fh.write("// Every index below comes from the offset-0 vtable of each side, of\n")
        fh.write("// equal length, dumped from the same game build. A class whose two\n")
        fh.write("// tables never agree in length is absent on purpose: equal length is\n")
        fh.write("// the evidence, and without it there is nothing but a guess.\n\n")
        for row in sorted(resolved, key=lambda r: (r["class"], r["win_index"])):
            fh.write(f'"{row["name"]}"\n{{\n')
            fh.write('\ttype    "func knownvtidx"\n')
            fh.write(f'\tvtable  "{row["class"]}"\n')
            fh.write(f'\tidx     "{row["win_index"]}"\n')
            fh.write(f'\t// {row["how"]}; linux +0x{row["offset"]:x}, windows 0x{row["win_addr"]:08x}\n')
            fh.write(f'\t// {row["sig"]}\n}}\n\n')
    print(f"\nwrote {len(resolved)} entries to {out}")


if __name__ == "__main__":
    main()
