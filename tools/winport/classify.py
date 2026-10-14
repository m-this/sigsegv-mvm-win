"""Classify sigsegv-mvm's Linux symbol addresses by how portable they are to Windows.

Every `type "sym"` entry resolves through LibMgr::FindSym against server_srv.so's
symbol table, which Windows server.dll does not have. A virtual function can be
reached by vtable index instead, which the mod already supports as
`func knownvtidx` and which needs no byte signature. So the first question for
each of the 1000-odd symbols is whether it is virtual.

mvm-reversed/Useful/vtable holds dumps of the Linux vtables, one file per class,
each line an offset, an address and a demangled signature. That is the answer
without downloading a game server.
"""
import re, subprocess, sys, json
from pathlib import Path
from collections import defaultdict

REPO = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/sigmod-probe")
GAMEDATA = REPO / "gamedata" / "sigsegv"
VTABLES = REPO / "mvm-reversed" / "Useful" / "vtable"

# Keys in this format are bare words and only values are quoted:
#     type "sym"
#     sym  "_ZN15CTFFlameThrower14SetWeaponStateEi"
# so a tokeniser that sees only quoted strings pairs the wrong halves together.
TOKEN = re.compile(r'//[^\n]*|"((?:[^"\\]|\\.)*)"|(\{)|(\})|([^\s{}"]+)')


def tokens(text):
    for m in TOKEN.finditer(text):
        if m.group(0).startswith("//"):
            continue
        quoted, opened, closed, bare = m.groups()
        if opened:
            yield ("open", None)
        elif closed:
            yield ("close", None)
        elif quoted is not None:
            # One symbol in the tree is written across a line break, which puts a
            # newline and four tabs inside the value. Left in, it makes c++filt
            # emit one line more than it was given and every name after it is
            # attributed to the wrong address.
            yield ("str", quoted.strip())
        elif bare is not None:
            yield ("str", bare.strip())


def parse(text):
    """A KeyValues tree: dict of key -> str | list[dict]. Duplicate keys are kept."""
    it = tokens(text)

    def block():
        out = defaultdict(list)
        pending = None
        for kind, value in it:
            if kind == "close":
                return out
            if kind == "str":
                if pending is None:
                    pending = value
                else:
                    out[pending].append(value)
                    pending = None
            elif kind == "open":
                out[pending if pending is not None else ""].append(block())
                pending = None
        return out

    return block()


def walk_addrs(node, found):
    """Collect every addr entry, from both the block form and the addrs_group form."""
    if not isinstance(node, defaultdict):
        return
    for key, values in node.items():
        for value in values:
            if not isinstance(value, defaultdict):
                continue
            if key == "addrs":
                for name, entries in value.items():
                    for entry in entries:
                        if isinstance(entry, defaultdict):
                            found.append((name, dict((k, v[0]) for k, v in entry.items()
                                                     if v and isinstance(v[0], str))))
            elif key == "addrs_group":
                common = {}
                for name, entries in value.items():
                    if name == "[common]":
                        for e in entries:
                            if isinstance(e, defaultdict):
                                common = dict((k, v[0]) for k, v in e.items()
                                              if v and isinstance(v[0], str))
                for name, entries in value.items():
                    if name == "[common]":
                        continue
                    for entry in entries:
                        if isinstance(entry, str):
                            found.append((name, {**common, "sym": entry}))
                        elif isinstance(entry, defaultdict):
                            found.append((name, {**common,
                                                 **dict((k, v[0]) for k, v in entry.items()
                                                        if v and isinstance(v[0], str))}))
            else:
                walk_addrs(value, found)


def demangle(symbols):
    """Batch through c++filt: one fork for a thousand names, not a thousand forks.

    Line in, line out, so anything that changes the line count silently shifts
    every name after it onto the wrong symbol. zip() would hide that. Refuse
    instead: a quietly misattributed signature becomes a wrong vtable index.
    """
    if not symbols:
        return {}
    clean = [re.sub(r"\s+", "", s) for s in symbols]
    out = subprocess.run(["c++filt", "-n"], input="\n".join(clean),
                         capture_output=True, text=True, check=True).stdout.splitlines()
    if len(out) != len(clean):
        raise SystemExit(f"c++filt returned {len(out)} lines for {len(clean)} symbols; "
                         "a symbol still carries a line break")
    return dict(zip(symbols, out))


def load_vtables():
    """demangled signature -> [(class, byte offset)], over every dumped library."""
    index = defaultdict(list)
    classes = 0
    line_re = re.compile(r"^\+0x([0-9a-fA-F]+):\s+[0-9a-fA-F]+\s+(.*)$")
    for lib in sorted(p for p in VTABLES.iterdir() if p.is_dir()):
        for dump in lib.glob("*.txt"):
            classes += 1
            owner = dump.stem
            for line in dump.read_text(errors="replace").splitlines():
                m = line_re.match(line.strip())
                if m:
                    index[m.group(2).strip()].append((owner, int(m.group(1), 16)))
    return index, classes


def main():
    entries = []
    for path in sorted(GAMEDATA.glob("*.txt")):
        found = []
        walk_addrs(parse(path.read_text(errors="replace")), found)
        for name, kv in found:
            entries.append((path.name, name, kv))

    by_type = defaultdict(list)
    for path, name, kv in entries:
        by_type[kv.get("type", "?")].append((path, name, kv))

    print(f"gamedata files      : {len(list(GAMEDATA.glob('*.txt')))}")
    print(f"addr entries parsed : {len(entries)}")
    for t, rows in sorted(by_type.items(), key=lambda kv: -len(kv[1])):
        print(f"  {t:<24} {len(rows)}")

    syms = [(p, n, kv) for p, n, kv in entries
            if kv.get("type") in ("sym", "sym regex") and "sym" in kv]
    mangled = sorted({kv["sym"] for _, _, kv in syms if kv["sym"].startswith("_Z")})
    names = demangle(mangled)

    index, classes = load_vtables()
    print(f"\nvtable dumps        : {classes} classes, {len(index)} distinct signatures")

    virtual, plain, regex, nonmangled = [], [], [], []
    for path, name, kv in syms:
        s = kv["sym"]
        if kv.get("type") == "sym regex":
            regex.append((path, name, s)); continue
        if not s.startswith("_Z"):
            nonmangled.append((path, name, s)); continue
        d = names.get(s, s)
        hits = index.get(d)
        if hits:
            virtual.append((path, name, d, hits[0]))
        else:
            plain.append((path, name, d))

    total = len(syms)
    print(f"\n--- the {total} symbol addresses ---")
    print(f"  virtual, in a dumped vtable : {len(virtual):>5}   -> func knownvtidx, no signature")
    print(f"  not in any vtable           : {len(plain):>5}   -> needs a scan strategy")
    print(f"  regex symbol match          : {len(regex):>5}")
    print(f"  non-mangled (C symbols)     : {len(nonmangled):>5}")

    lib_split = defaultdict(int)
    for path, name, kv in syms:
        lib_split[kv.get("lib", "server")] += 1
    print("\n  by library:")
    for lib, n in sorted(lib_split.items(), key=lambda kv: -kv[1]):
        print(f"    {lib:<14} {n}")

    Path("/tmp/sigport/classified.json").write_text(json.dumps({
        "virtual": [{"file": p, "name": n, "sig": d, "class": h[0], "offset": h[1]}
                    for p, n, d, h in virtual],
        "needs_scan": [{"file": p, "name": n, "sig": d} for p, n, d in plain],
        "regex": [{"file": p, "name": n, "sym": s} for p, n, s in regex],
        "nonmangled": [{"file": p, "name": n, "sym": s} for p, n, s in nonmangled],
    }, indent=2))
    print("\nwrote /tmp/sigport/classified.json")


if __name__ == "__main__":
    main()
