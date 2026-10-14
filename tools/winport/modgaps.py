#!/usr/bin/env python3
"""Which of a mod's detours and virtual hooks have no Windows address.

Reads every MOD_ADD_DETOUR_* and MOD_ADD_VHOOK* in src/, attributes each to
the mod whose constructor registers it, and looks its address name up in
gamedata/sigsegv/windows.txt. Code under `#if 0` or `#if !defined _WINDOWS`
is skipped, as is anything commented out. An override marked bad counts as
missing, which is what emitgamedata.py makes of it.

A missing detour loads its mod without that detour; a missing virtual hook
fails the whole mod, so the two are listed apart.

    modgaps.py                          every mod with a gap, and the gaps
    modgaps.py "Pop:TFBot_Extensions" ...    those mods only, with a count of
                                             how many of them need each target
    modgaps.py --bed LOG ...            also what a bed's log says it refused
                                        or could not hook at load
"""

import collections
import glob
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import classify  # noqa: E402

root = Path(__file__).resolve().parents[2]

windows = {}
for m in re.finditer(r'^\t\t\t\t"([^"]+)"\n\t\t\t\t\{\n(.*?)\n\t\t\t\t\}', (root / "gamedata/sigsegv/windows.txt").read_text(), re.M | re.S):
    windows[m.group(1)] = m.group(2)

args = sys.argv[1:]
refused, hookfail = set(), set()
if args[:1] == ["--bed"]:
    log = open(args[1], errors="replace").read()
    refused = set(re.findall(r'refused detour: [^"\n]*"([^"]+)"', log))
    hookfail = set(re.findall(r'CVirtualHook::FAIL "([^"]+)"', log))
    args = args[2:]

bad = {sym for sym, e in json.load(open(Path(__file__).parent / "overrides.json")).items() if e.get("bad")}

# How Linux finds each name, to say what kind of gap it is.
linux = {}
for path in sorted(glob.glob(str(root / "gamedata/sigsegv/*.txt"))):
    if not path.endswith("windows.txt"):
        found = []
        classify.walk_addrs(classify.parse(open(path).read()), found)
        for name, entry in found:
            if entry.get("sym") or name not in linux:
                linux[name] = entry
        # classify.py loses some addrs_group pairs; emitgamedata.py reads
        # them the same way.
        common = {}
        for line in open(path).read().split("\n"):
            line = line.split("//")[0].strip()
            kv = re.match(r'^(type|lib)\s+"([^"]*)"$', line)
            if kv:
                common[kv.group(1)] = kv.group(2)
            pair = re.match(r'^"([^"]+)"\s+"([^"]+)"$', line)
            if pair and not pair.group(1).startswith("_Z") and not linux.get(pair.group(1), {}).get("sym"):
                linux[pair.group(1)] = {"type": common.get("type"), "sym": pair.group(2)}
for path in glob.glob(str(root / "src/addr/*.cpp")):
    text = open(path).read()
    for m in re.finditer(r'GetName\(\) const override\s*\{\s*return "([^"]+)"', text):
        linux.setdefault(m.group(1), {"type": "code"})
    # An interface's virtual, read off the interface pointer at run time.
    for m in re.finditer(r'CAddr_InterfaceVFunc\(&\w+, "(\w+)"', text):
        cls = re.search(r"class (CAddr_\w+) : public CAddr_InterfaceVFunc[^{]*\{[^}]*" + re.escape(m.group(0)), text)
        if cls:
            for f in re.finditer(r"static " + cls.group(1) + r' \w+\s*\("(\w+)"', text):
                linux.setdefault(f"{m.group(1)}::{f.group(1)}", {"type": "code"})


def preprocess(text):
    """The text with comments and code Windows never compiles blanked out."""
    text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    out, stack = [], []
    for line in text.split("\n"):
        s = line.strip()
        d = re.match(r"#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)", s)
        if d:
            kind, cond = d.group(1), d.group(2).strip()
            if kind in ("if", "ifdef", "ifndef"):
                if kind == "ifdef":
                    cond = f"defined {cond}"
                elif kind == "ifndef":
                    cond = f"!defined {cond}"
                stack.append(evaluate(cond))
            elif kind == "elif":
                stack[-1] = evaluate(cond) if stack[-1] is False else False
            elif kind == "else":
                stack[-1] = None if stack[-1] is None else not stack[-1]
            elif kind == "endif":
                stack.pop()
            out.append("")
            continue
        out.append(line if all(x is not False for x in stack) else "")
    return "\n".join(out)


def evaluate(cond):
    """True or False for the conditions that decide Windows, None (kept) otherwise."""
    cond = cond.replace("(", " ").replace(")", " ").split("//")[0].strip()
    if cond == "0":
        return False
    if cond == "1":
        return True
    m = re.fullmatch(r"(!?)\s*defined\s+(_WINDOWS|_MSC_VER|_LINUX|__GNUC__|PLATFORM_64BITS)", cond)
    if m:
        on = m.group(2) in ("_WINDOWS", "_MSC_VER")
        return on != bool(m.group(1))
    return None


# The address name is the last string argument: a virtual hook may name its
# vtable with a string too.
ADD = re.compile(r'MOD_ADD_(DETOUR_MEMBER|DETOUR_STATIC|VHOOK|VHOOK2|VHOOK_INHERIT)(?:_PRIORITY)?\s*\(\s*(\w+)\s*,[^;]*"([^"]+)"[^";]*\)\s*;')

mods = collections.OrderedDict()
for path in sorted(glob.glob(str(root / "src/**/*.cpp"), recursive=True)):
    text = preprocess(open(path).read())
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'IMod\("([^"]+)"\)', text)]
    if not starts:
        continue
    for m in ADD.finditer(text):
        owner = None
        for pos, name in starts:
            if pos < m.start():
                owner = name
        if owner is None:
            owner = starts[0][1]
        kind = "vhook" if m.group(1).startswith("VHOOK") else "detour"
        mods.setdefault(owner, []).append((kind, m.group(3), path[len(str(root)) + 1:], text.count("\n", 0, m.start()) + 1))


def status(name, kind):
    if kind == "detour" and name in refused:
        return "refused"
    if kind == "vhook" and name in hookfail:
        return "failed"
    entry = windows.get(name)
    if entry is None:
        e = linux.get(name, {})
        if e.get("sym") in bad:
            return "bad"
        # Found at run time without a table entry: a slot in a table MSVC's
        # RTTI names (whose index still wants checking against this build),
        # a prologue near a unique string, or code in src/addr.
        if e.get("type") == "code" or (e.get("type") == "func knownvtidx" and e.get("vtable", "").startswith(".?AV")) \
                or (e.get("type") or "").startswith("func ebpprologue"):
            return "runtime"
        return "missing"
    sym = re.search(r'sym\s+"([^"]+)"', entry)
    if sym and sym.group(1) in bad:
        return "bad"
    return None


def describe(name):
    e = linux.get(name)
    if e is None:
        return "not in the Linux gamedata"
    t = e.get("type", "?")
    return f'{t} {e["sym"]}' if e.get("sym") else t


wanted = args or list(mods)
need = collections.defaultdict(set)
for mod in wanted:
    if mod not in mods:
        print(f"{mod}: no registrations found", file=sys.stderr)
        continue
    gaps = [(kind, name, where, line, status(name, kind)) for kind, name, where, line in mods[mod] if status(name, kind)]
    if not gaps and not args:
        continue
    total = collections.Counter(kind for kind, *_ in mods[mod])
    print(f"== {mod}: {sum(g[4] != 'runtime' for g in gaps)} of {total['detour']} detours + {total['vhook']} vhooks have no usable address, "
          f"{sum(g[4] == 'runtime' for g in gaps)} more are found at run time")
    for kind, name, where, line, st in sorted(gaps, key=lambda g: (g[4] == "runtime", g[0] != "vhook", g[1])):
        print(f"  {kind:6} {st:7} {name:60} {describe(name)}  ({where}:{line})")
        if st != "runtime":
            need[(kind, name)].add(mod)

if args:
    print(f"\n== targets by how many of the {len(wanted)} mods need them")
    for (kind, name), who in sorted(need.items(), key=lambda kv: (-len(kv[1]), kv[0][0] != "vhook", kv[0][1])):
        print(f"  {len(who)}  {kind:6} {name:60} {', '.join(sorted(who))}")
