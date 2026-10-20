#!/usr/bin/env python3
"""The extension sources the Windows package compiles, one per line.

    shipped.py [REPO]

AMBuilder's list, with the groups configure.py can already leave out left
out: they are tools for working on the mod rather than for running missions,
and debug and visualize carry code that was only ever built for Linux, and in
one case for a 2017 Windows client. Upstream's Linux packages leave out the
same three (autoconfig.sh). build.sh compiles this list; modgaps.py and
namegaps.py count against it with --shipped, reading each file through
preprocess() so code Windows never compiles does not count.
"""

import re
import sys
import types
from pathlib import Path

# Sources that are Linux by design rather than by accident, each with why.
LINUX_ONLY = {
    # Watches the workshop map folder with inotify.
    "src/mod/etc/workshop_map_fix.cpp",
}


def sources(root):
    text = (Path(root) / "AMBuilder").read_text()
    ext = types.SimpleNamespace(name="sigsegv", exclude=["mods_debug", "mods_visualize", "mods_vgui"], optimize_mods_only=False)
    scope = {"Extension": ext}
    exec(text[:text.index("project = builder.LibraryProject")], scope)
    return sorted(set(scope["sourceFiles"]) - LINUX_ONLY)


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
    if "&&" in cond and "||" not in cond:
        terms = [evaluate(t) for t in cond.split("&&")]
        return False if False in terms else True if all(terms) else None
    if "||" in cond and "&&" not in cond:
        terms = [evaluate(t) for t in cond.split("||")]
        return True if True in terms else False if all(t is False for t in terms) else None
    if cond == "0":
        return False
    if cond == "1":
        return True
    m = re.fullmatch(r"(!?)\s*defined\s+(_WINDOWS|_MSC_VER|_LINUX|__GNUC__|PLATFORM_64BITS)", cond)
    if m:
        on = m.group(2) in ("_WINDOWS", "_MSC_VER")
        return on != bool(m.group(1))
    return None


if __name__ == "__main__":
    for f in sources(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]):
        print(f)
