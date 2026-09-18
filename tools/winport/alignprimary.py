#!/usr/bin/env python3
"""Why a class's two primary vtables differ in length, and whether that is fixable.

matchvtables.py derives a vtable index only when the two offset-0 tables are the
same length, because equal length is the evidence. 104 classes are refused for
differing, CTFPlayer at 496 Linux slots against 490 and CTFBot at 538 against
495, and this is the tool for reading those.

    alignprimary.py LINUX-VTABLES WIN-VTABLES MATCHES.JSON [CLASS...]

With classes named, it prints their alignment slot by slot. With none, it runs
the whole corpus and reports what the rule below explains.

## The rule

Itanium emits an interface override in the primary table AND as a thunk in the
interface's own secondary table. MSVC emits it only in the interface's table.
So a Linux primary carries slots a Windows primary does not, one per interface
method the class overrides.

CTFPlayer is the worked example. Its two dumps carry three secondary tables
each and they align one for one:

    linux 0x1250  3 slots  CAI_ExpresserSink          <-> windows 0x1238  3
    linux 0x129c  5 slots  IHasAttributes thunks      <-> windows 0x1284  5
    linux 0x12a0  8 slots  IInventoryUpdateListener   <-> windows 0x1288  8

and the six slots the Windows primary lacks are exactly the ones thunked
there: GetAttributeManager, GetAttributeContainer, GetAttributeOwner,
GetAttributeList, ReapplyProvision, InventoryUpdated, SOCacheUnsubscribed.

## What the rule is not

Dropping those slots makes 160 of the 334 unequal classes equal in length. Do
not stop there. Checked against the functions matchfuncs.py matched by string
on both sides, only 6 of those 160 have every anchor land on its own slot: 145
are off locally, usually by two, because MSVC also reverses a run of overloads
declared together. CTFPlayer's KeyValue run is the visible case, linux slots
31, 32, 33 against windows 33, 32, 31.

So equal length after the drop is a candidate, not a result. A class earns an
index when its anchors agree, which is what --verify reports.
"""

import collections
import json
import os
import re
import subprocess
import sys

WINDOWS_IMAGE_BASE = 0x10000000
THUNK = re.compile(r"^(?:non-virtual|virtual) thunk to (.*)$")


def tables(path):
    """Every sub-table in a dump: its offset in the complete object -> slots."""
    out, current = collections.OrderedDict(), None
    for line in open(path, encoding="utf-8", errors="replace"):
        header = re.match(r"^// vtable at 0x([0-9a-f]+) offset 0x([0-9a-f]+)", line)
        if header:
            current = int(header[2], 16)
            out.setdefault(current, [])
            continue
        slot = re.match(r"^\+0x([0-9a-f]+):\s+([0-9a-f]+)(?:\s+(.*))?$", line.rstrip())
        if slot and current is not None:
            out[current].append((int(slot[2], 16), (slot[3] or "").strip()))
    return out


def collapse_destructors(slots):
    """Itanium emits two destructor slots where MSVC emits one."""
    out, i = [], 0
    while i < len(slots):
        same = i + 1 < len(slots) and slots[i][1] and slots[i][1] == slots[i + 1][1]
        if same and "~" in slots[i][1]:
            out.append(slots[i])
            i += 2
        else:
            out.append(slots[i])
            i += 1
    return out


def thunked_names(secondaries):
    """The functions the secondary tables reach through a thunk."""
    names = set()
    for table in secondaries:
        for _, name in table:
            match = THUNK.match(name)
            if match:
                names.add(match[1])
    return names


def drop_interface_duplicates(primary, secondaries):
    names = thunked_names(secondaries)
    return [slot for slot in primary if slot[1] not in names], names


def windows_address_by_name(matches_path):
    """Demangled Linux name -> the Windows address matchfuncs.py gave it."""
    matches = json.load(open(matches_path))
    keys = list(matches)
    demangled = subprocess.run(
        ["c++filt", "-n"], input="\n".join(keys), capture_output=True, text=True
    ).stdout.split("\n")
    out = {}
    for key, name in zip(keys, demangled):
        name = name.strip()
        if name:
            out.setdefault(name, matches[key]["rva"] + WINDOWS_IMAGE_BASE)
    return out


def anchors(linux_primary, windows_primary, by_name):
    """Slots whose function matchfuncs.py placed at an unambiguous Windows address.

    An address in more than one slot cannot say which slot it is, so it is not
    an anchor.
    """
    seen = collections.Counter(address for address, _ in windows_primary)
    out = []
    for index, (_, name) in enumerate(linux_primary):
        address = by_name.get(name)
        if address is None or index >= len(windows_primary):
            continue
        if seen[windows_primary[index][0]] != 1:
            continue
        out.append((index, name, windows_primary[index][0] == address))
    return out


def classes(linux_dir, windows_dir):
    for entry in sorted(os.listdir(linux_dir)):
        if not entry.endswith(".txt"):
            continue
        name = entry[:-4]
        if os.path.exists(os.path.join(windows_dir, entry)):
            yield name


def report_one(name, linux_dir, windows_dir, by_name):
    linux, windows = tables(f"{linux_dir}/{name}.txt"), tables(f"{windows_dir}/{name}.txt")
    if 0 not in linux or 0 not in windows:
        print(f"{name}: no offset-0 table on one side")
        return
    primary = collapse_destructors(linux[0])
    secondaries = [slots for offset, slots in linux.items() if offset != 0]
    dropped, names = drop_interface_duplicates(primary, secondaries)
    print(f"{name}: linux {len(primary)} collapsed, windows {len(windows[0])}, "
          f"delta {len(primary) - len(windows[0])}")
    print(f"  interface methods thunked in a secondary table: {len(names)}")
    print(f"  linux primary after dropping them: {len(dropped)}")
    for offset, slots in linux.items():
        if offset:
            print(f"    linux secondary 0x{offset:x}: {len(slots)} slots")
    for offset, slots in windows.items():
        if offset:
            print(f"    windows secondary 0x{offset:x}: {len(slots)} slots")
    agreed = anchors(dropped, windows[0], by_name)
    good = sum(1 for _, _, ok in agreed if ok)
    print(f"  anchors: {good} of {len(agreed)} land on their own slot")
    for index, fname, ok in agreed:
        if not ok:
            print(f"    disagrees at slot {index}: {fname}")


def report_all(linux_dir, windows_dir, by_name):
    counts = collections.Counter()
    verified, unverified, remaining = [], [], []
    for name in classes(linux_dir, windows_dir):
        linux, windows = tables(f"{linux_dir}/{name}.txt"), tables(f"{windows_dir}/{name}.txt")
        if 0 not in linux or 0 not in windows:
            continue
        primary, wprimary = collapse_destructors(linux[0]), windows[0]
        if len(primary) == len(wprimary):
            counts["equal already"] += 1
            continue
        secondaries = [slots for offset, slots in linux.items() if offset != 0]
        dropped, _ = drop_interface_duplicates(primary, secondaries)
        if len(dropped) != len(wprimary):
            counts["still unequal"] += 1
            remaining.append((name, len(primary), len(wprimary), len(dropped)))
            continue
        counts["equal after the rule"] += 1
        agreed = anchors(dropped, wprimary, by_name)
        good = sum(1 for _, _, ok in agreed if ok)
        if not agreed:
            counts["  no anchor to check"] += 1
        elif good == len(agreed):
            counts["  every anchor agrees"] += 1
            verified.append((name, len(dropped), len(agreed)))
        else:
            counts["  an anchor disagrees"] += 1
            unverified.append((name, good, len(agreed)))
    for key, n in counts.items():
        print(f"{n:6}  {key}")
    print(f"\nclasses the rule explains and the anchors confirm ({len(verified)}):")
    for name, slots, n in verified:
        print(f"  {name:44} {slots:4} slots, {n} anchors")
    print(f"\nexplained by length, refused by anchors ({len(unverified)}), worst first:")
    for name, good, n in sorted(unverified, key=lambda r: r[1] - r[2])[:20]:
        print(f"  {name:44} {good}/{n} anchors agree")
    print(f"\nstill unequal after the rule ({len(remaining)}), worst first:")
    for name, l, w, d in sorted(remaining, key=lambda r: -(r[1] - r[2]))[:20]:
        print(f"  {name:44} linux {l:4} windows {w:4} after the drop {d:4}")


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    linux_dir, windows_dir, matches_path = sys.argv[1:4]
    by_name = windows_address_by_name(matches_path)
    named = sys.argv[4:]
    if named:
        for name in named:
            report_one(name, linux_dir, windows_dir, by_name)
    else:
        report_all(linux_dir, windows_dir, by_name)


if __name__ == "__main__":
    main()
