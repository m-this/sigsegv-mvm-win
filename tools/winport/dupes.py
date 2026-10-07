#!/usr/bin/env python3
"""Count the address blocks a Windows server registers twice under one name.

    dupes.py [REPO] [--table windows.txt]

AddrManager::Load keeps the first IAddr registered under a name and prints
"duplicate addr for" for every other one. On Windows the extension loads
gamedata/sigsegv/windows.txt first, then the files in src/gameconf.cpp's
configs[], and CSigsegvGameConf::NameTaken leaves out any block whose name an
earlier one holds. What a name that survives that rule means is one block
that never had a chance, so this fails on:

- a name twice in windows.txt: emitgamedata.py writes each name once;
- a name twice among the other files: the later block is dead on Windows and
  prints on Linux.

A block of another file under a name windows.txt holds is the rule working
and is only counted. --table reads another file in place of windows.txt, the
Address table job's derived one.

The reader follows SourceMod's ParseStream_SMC rather than classify.py's: a
quote ends at the closing quote or at the end of the line, which is what makes
misc.txt's unterminated symbol harmless to the game and fatal to a tokeniser
that pairs quotes across lines. Static IAddrs in src/addr are not read; the
loader covers them, and FireEvent is the one that collides.

Needs nothing but Python. Exits 1 and names each repeated name.
"""

import re
import sys
from pathlib import Path


def tokens(text):
    """(line, kind, value) the way ParseStream_SMC stages them."""
    in_comment = False
    for number, line in enumerate(text.split("\n"), 1):
        i = 0
        while i < len(line):
            char = line[i]
            if in_comment:
                end = line.find("*/", i)
                if end < 0:
                    break
                in_comment, i = False, end + 2
            elif char in " \t\r":
                i += 1
            elif char == ";" or line.startswith("//", i):
                break
            elif line.startswith("/*", i):
                in_comment, i = True, i + 2
            elif char in "{}":
                yield number, char, None
                i += 1
            elif char == '"':
                end = i + 1
                while end < len(line) and not (line[end] == '"' and line[end - 1] != "\\"):
                    end += 1
                yield number, "str", line[i + 1:end]
                i = end + 1
            else:
                end = i
                while end < len(line) and line[end] not in ' \t\r"{};' and not line.startswith("//", end):
                    end += 1
                yield number, "str", line[i:end]
                i = end
        yield number, "eol", None


def pairs(text):
    """(line, event, a, b): `open` a section named a, `pair` a b, `close`."""
    staged = []
    for number, kind, value in tokens(text):
        if kind == "str":
            staged.append(value)
        elif kind == "{":
            yield number, "open", staged[-1] if staged else "", None
            staged = []
        elif kind == "}":
            if len(staged) == 2:
                yield number, "pair", staged[0], staged[1]
            staged = []
            yield number, "close", None, None
        elif len(staged) >= 2:
            if len(staged) > 2:
                raise ValueError(f"line {number}: {len(staged)} strings in a row")
            yield number, "pair", staged[0], staged[1]
            staged = []


def blocks(text):
    """(name, line, keyvalues) for each address SigMod registers from one file.

    An `addrs` section holds one block per name. An `addrs_group` holds a
    [common] block and a name to symbol pair per address, in a map: a name
    twice in one group is one address, the later value.
    """
    sections, out = [], []
    group = None
    for number, event, a, b in pairs(text):
        if event == "open":
            sections.append({"name": a, "line": number, "kv": {}})
            if a == "addrs_group":
                group = {"common": {}, "entries": {}}
        elif event == "pair":
            top = sections[-1]
            if top["name"] == "[common]":
                group["common"][a] = b
            elif top["name"] == "addrs_group":
                group["entries"][a] = (b, number)
            else:
                top["kv"][a] = b
        else:
            top = sections.pop()
            if sections and sections[-1]["name"] == "addrs":
                out.append((top["name"], top["line"], top["kv"]))
            elif top["name"] == "addrs_group":
                common = group["common"]
                for key, (symbol, line) in group["entries"].items():
                    name = key + "::m_DataMap" if common.get("type") == "datamap" else key
                    out.append((name, line, {**common, "sym": symbol}))
    return out


def configs(root):
    """The gamedata files a Windows server loads, in the order it loads them."""
    source = (root / "src/gameconf.cpp").read_text()
    names = re.findall(r'^\s*"(sigsegv/[^"]+)"', source, re.M)
    if not names or names[0] != "sigsegv/windows":
        raise SystemExit("src/gameconf.cpp: configs[] does not start with sigsegv/windows")
    return names


def loaded(root, table=None):
    """(file, line, name, keyvalues) for every block, in load order."""
    out = []
    for config in configs(root):
        path = Path(table) if table and config == "sigsegv/windows" else root / "gamedata" / f"{config}.txt"
        out += [(config, line, name, kv) for name, line, kv in blocks(path.read_text())]
    return out


def strategy(kv):
    return f"{kv.get('type')} {kv.get('addr') or ''}".strip()


def report(root, table=None):
    """(summary lines, problem lines)."""
    owner, problems, left_out, lines_before = {}, [], 0, 0
    everything = loaded(root, table)
    for config, line, name, kv in everything:
        if name not in owner:
            owner[name] = (config, line, kv)
            continue
        first = owner[name]
        lines_before += 1
        if first[0] == "sigsegv/windows" and config != "sigsegv/windows":
            left_out += 1
        else:
            problems.append(f'"{name}": {first[0]}:{first[1]} ({strategy(first[2])}) and {config}:{line} ({strategy(kv)})')
    summary = [
        f"{len(everything)} blocks under {len(owner)} names in the {len(configs(root))} files a Windows server loads",
        f"{lines_before} \"duplicate addr for\" lines before CSigsegvGameConf::NameTaken, {len(problems)} after it",
        f"{left_out} blocks left out because windows.txt holds their name",
    ]
    return summary, problems


def main():
    args = sys.argv[1:]
    table = None
    if "--table" in args:
        at = args.index("--table")
        table = args[at + 1]
        del args[at:at + 2]
    root = Path(args[0]) if args else Path(__file__).resolve().parents[2]
    summary, problems = report(root, table)
    print("\n".join(summary))
    if problems:
        sys.exit("\n".join(["a name is registered twice:"] + problems[:50] + ([f"... and {len(problems) - 50} more"] if len(problems) > 50 else [])))


if __name__ == "__main__":
    main()
