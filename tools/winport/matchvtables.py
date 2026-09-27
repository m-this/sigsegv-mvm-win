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
    return [name for _, name in read_linux_addressed(path)]


def read_linux_addressed(path):
    """read_linux, with each slot's address."""
    slots, offset = [], 0
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        header = LINUX_HEADER.match(line)
        if header:
            offset = int(header.group(1), 16)
            continue
        m = LINUX_LINE.match(line)
        if m and offset == 0:
            slots.append((int(line.split()[1], 16), m.group(2).strip()))
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


# Groups a class declares, by overriding an inherited virtual of the same name,
# before any of its new virtuals, so its new overloads of them come first. Read
# from the SDK and confirmed by hand: CGameMovement's slot 12 is
# PlayerSolidMask, two past where Linux order puts it (overrides.json).
DECLARED_FIRST = {
    "CGameMovement": ("GetPlayerMins", "GetPlayerMaxs"),
}


class Corpus:
    """Every Linux primary table, for telling a class's own new virtuals from
    the ones it inherits.

    The dumps carry no base classes, but a primary base's table is a prefix of
    the derived class's, slot for slot by name and parameters. The longest
    other table this one starts with is taken as its primary base, and the
    slots past it are the class's own new virtuals. A base missing from
    that search merges two classes' runs into one, which only matters when
    both declare the same name.

    A slot's name is the first name nm gives its address, and GCC folds
    identical bodies: `return NULL` fills dozens of slots under one of their
    names. A body seen at two slot indices is therefore not named at all here.
    It matches anything and groups with nothing, which is right for MSVC too,
    since it folds the same bodies and every slot of one holds one address.
    """

    def __init__(self, linux_dir):
        rows, self.pretty = {}, {}
        for path in sorted(Path(linux_dir).glob("*.txt")):
            got = read_linux_addressed(path)
            if got:
                rows[path.stem] = got
                head = path.read_text(errors="replace").split("\n", 1)[0].strip()
                self.pretty[path.stem] = head if head and not head.startswith(("//", "+")) else path.stem
        self.stem = {pretty: stem for stem, pretty in self.pretty.items()}
        self.tables = {cls: [name for _, name in got] for cls, got in rows.items()}

        seen = defaultdict(set)
        for got in rows.values():
            for index, (addr, _) in enumerate(got):
                seen[addr].add(index)
        self.folded = {addr for addr, where in seen.items() if len(where) > 1}
        self.names = {
            cls: [None if addr in self.folded or unnamed(name) else name for addr, name in got]
            for cls, got in rows.items()
        }
        self.keys = {cls: [slot_key(n) if n else None for n in names] for cls, names in self.names.items()}
        # Tables with nothing named but destructors: interfaces, whose slots
        # are all pure. Nothing says which class implements one, so any class
        # that implements every slot of it itself is taken to.
        # Every table under its last named slot: a base's last slot is where
        # the derived class's table carries the same key, so looking up each of
        # a class's slots finds its bases without walking every table. Tables
        # with the same keys are one entry, and it is the class that declares
        # that last slot itself where there is one: a class that adds nothing
        # has its base's keys, and the base is the one whose own declarations
        # the order has to look at.
        self.ending = defaultdict(dict)
        for cls in sorted(self.keys):
            keys = self.keys[cls]
            last = max((i for i, k in enumerate(keys) if k is not None), default=None)
            if last is None:
                continue
            entry = self.ending[(last, keys[last])]
            held = entry.get(tuple(keys))
            if held is None or (not self.declares_last(held) and self.declares_last(cls)):
                entry[tuple(keys)] = cls
        self.interfaces = [c for c, k in self.keys.items()
                           if all(x in (None, "~") for x in k) and any(unnamed(n) for n in self.tables[c])]
        self._orders = {}
        # Classes that add an overload of a name they also override, for the
        # log: the one place the order rests on an assumption (see order).
        self.ambiguous = {}

    def declares_last(self, cls):
        named = [n for n in self.names[cls] if n]
        return bool(named) and split_name(named[-1])[0] == self.pretty[cls]

    def starts_with(self, cls, other):
        mine, theirs = self.keys[cls], self.keys[other]
        return len(theirs) < len(mine) and all(t is None or k is None or t == k for t, k in zip(theirs, mine))

    def parent(self, cls):
        """The longest other table this one starts with, or None."""
        own, keys = self.pretty[cls], self.keys[cls]
        candidates = {self.stem.get(split_name(n)[0]) for n in self.names[cls] if n}
        for at, key in enumerate(keys):
            if key is not None:
                candidates.update(self.ending.get((at, key), {}).values())
        candidates -= {None, cls}
        # Longest first, and of two the same, the one that declares its last
        # slot: the other added nothing to it (see `ending`).
        ranked = sorted(candidates, key=lambda c: (-len(self.keys[c]), not self.declares_last(c), c))
        best = next((c for c in ranked if self.starts_with(cls, c)), None)
        floor = len(self.keys[best]) if best else 0
        for other in sorted(self.interfaces):
            size = len(self.keys[other])
            if size <= floor or other == cls or not self.starts_with(cls, other):
                continue
            if all(n is None or split_name(n)[0] == own for n in self.names[cls][:size]):
                best, floor = other, size
        return best

    def order(self, cls):
        """The Linux slot indices of `cls` in the order MSVC lays them out.

        A class's own new virtuals are grouped by name. A group goes where the
        class first declares that name. That is its first new virtual of the
        name, unless the class also overrides an inherited virtual of the same
        name and declares the override earlier. The binary does not record
        where an override is declared, and it goes both ways: CGameMovement
        declares GetPlayerMins(bool) at the top and GetPlayerMins() far below,
        CBasePlayer declares ChangeTeam(int) just above its new overload. So a
        group stays at its first new virtual unless DECLARED_FIRST says
        otherwise, and every class that could go either way is recorded in
        `ambiguous`.
        """
        if cls in self._orders:
            return self._orders[cls]
        slots = self.names[cls]
        base = self.parent(cls)
        inherited = list(self.order(base)) if base else []
        start = len(self.tables[base]) if base else 0
        own = self.pretty[cls]

        overridden = set()
        for j in range(start):
            if slots[j] and split_name(slots[j])[0] == own:
                overridden.add(method(slots[j]))
        groups = {}
        for i in range(start, len(slots)):
            groups.setdefault(method(slots[i]) if slots[i] else ("#", i), []).append(i)
        first = [g for g in DECLARED_FIRST.get(own, ()) if g in groups]
        rest = [g for g in groups if g not in first]
        unsure = [g for g in rest if g in overridden and g != rest[0]]
        if unsure:
            self.ambiguous[cls] = unsure
        # The destructor's two Itanium slots are one to MSVC, and keep their order.
        new = [i for g in first + rest for i in (groups[g] if g == "~" else reversed(groups[g]))]
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
    if corpus.ambiguous:
        print("\n  new overloads of a name the class also overrides, kept where Linux has them:")
        for cls, names in sorted(corpus.ambiguous.items()):
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
