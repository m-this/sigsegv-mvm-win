"""Align a Linux vtable against its Windows twin and emit `func knownvtidx`.

Both vtables are generated from the same class definition, so their slots are
the same functions in almost the same order. Only the Linux side carries names.
Turning a Linux slot into a Windows index is therefore an alignment problem, and
the two ABIs differ in exactly two ways that matter here:

  * Destructors. The Itanium ABI emits two slots, the complete object destructor
    and the deleting destructor, and they appear in the dump as the same
    signature twice in a row. MSVC emits one, the vector deleting destructor.
  * Overloads. MSVC reverses a run of overloads declared together in one class.
    Itanium keeps declaration order.

Neither rule applies to every class, and which of them applies is not something
the dumps record, so this tries each combination and keeps the one that makes
the two tables the same length. Equal length is evidence, not proof: it is
strong for a class with one vtable and worth nothing for one with several, which
is why a class MSVC gave more than one vtable is refused outright.

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


def read_linux(path):
    slots = []
    for line in path.read_text(errors="replace").splitlines():
        m = LINUX_LINE.match(line.strip())
        if m:
            slots.append(m.group(2).strip())
    return slots


def read_windows(path):
    """Only the first vtable in a file: extra ones are secondary bases."""
    slots, seen_header = [], False
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("// vtable at"):
            if seen_header:
                break
            seen_header = True
            continue
        m = WIN_LINE.match(line)
        if m:
            slots.append(int(m.group(2), 16))
    return slots


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


def reverse_overload_runs(slots):
    """MSVC lays a run of same-named virtuals out backwards."""
    out, i = [], 0
    while i < len(slots):
        j = i
        while j + 1 < len(slots) and bare_name(slots[j + 1]) == bare_name(slots[i]):
            j += 1
        run = slots[i:j + 1]
        out.extend(reversed(run) if len(run) > 1 else run)
        i = j + 1
    return out


ALIGNMENTS = (
    ("raw", lambda s: s),
    ("collapse", collapse_destructors),
    ("collapse+reverse", lambda s: reverse_overload_runs(collapse_destructors(s))),
    ("reverse", reverse_overload_runs),
)


def align(linux, windows):
    """The first transform that makes the tables agree in length, or None."""
    for name, transform in ALIGNMENTS:
        candidate = transform(linux)
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

    resolved, refused, missing, multi = [], [], [], []
    used = defaultdict(int)
    for cls, rows in sorted(wanted.items()):
        linux_path, win_path = linux_dir / f"{cls}.txt", win_dir / f"{cls}.txt"
        if not linux_path.exists() or not win_path.exists():
            missing.append((cls, len(rows)))
            continue
        if count_tables(win_path) > 1:
            # Several vtables means multiple inheritance, and then a single
            # length is not evidence of anything.
            multi.append((cls, len(rows)))
            continue
        linux, windows = read_linux(linux_path), read_windows(win_path)
        how, aligned = align(linux, windows)
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
    print(f"  several windows vtables: {sum(m[1] for m in multi)} in {len(multi)} classes")
    print(f"  no alignment fits      : {sum(r[3] for r in refused)} in {len(refused)} classes")
    print(f"  no dump on one side    : {sum(m[1] for m in missing)} in {len(missing)} classes")
    if used:
        print("\n  alignment used, by class:")
        for how, n in sorted(used.items(), key=lambda kv: -kv[1]):
            print(f"    {how:<18} {n}")
    if refused:
        print("\n  refused, worst first (class: linux slots vs windows slots):")
        for cls, ln, wn, n in sorted(refused, key=lambda r: -r[3])[:8]:
            print(f"    {cls:<42} {ln:>4} vs {wn:<4}  costs {n}")

    out = Path("winport_knownvtidx.txt")
    with out.open("w") as fh:
        fh.write("// Generated by tools/winport/matchvtables.py. Do not hand-edit.\n")
        fh.write("// Every index below comes from a Linux and a Windows vtable of equal\n")
        fh.write("// length for a class MSVC gave exactly one vtable. Classes with several\n")
        fh.write("// vtables, or whose lengths never agree, are absent on purpose.\n\n")
        for row in sorted(resolved, key=lambda r: (r["class"], r["win_index"])):
            fh.write(f'"{row["name"]}"\n{{\n')
            fh.write('\ttype    "func knownvtidx"\n')
            fh.write(f'\tvtable  "{row["class"]}"\n')
            fh.write(f'\tidx     "{row["win_index"]}"\n')
            fh.write(f'\t// {row["how"]}; linux +0x{row["offset"]:x}, windows 0x{row["win_addr"]:08x}\n')
            fh.write(f'\t// {row["sig"]}\n}}\n\n')
    print(f"\nwrote {len(resolved)} entries to {out}")


main()
