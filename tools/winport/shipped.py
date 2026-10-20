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

# Sources the Windows package leaves out, each with why (WINDOWS_COVERAGE.md).
LINUX_ONLY = {
    # Watches the workshop map folder with inotify.
    "src/mod/etc/workshop_map_fix.cpp",
    # Replaces two functions whole, which CFuncReplace cannot size under MSVC,
    # and nine of its detours have no Windows address. Off by default.
    "src/mod/perf/sendprop_optimize.cpp",
}

# What a TF2 server.dll build defines (AMBuildScript, src/common.h) and what it
# does not.
DEFINED = {"_WINDOWS", "_MSC_VER", "SE_IS_TF2", "SE_IS_SDK2013_BASED"}
UNDEFINED = {"_LINUX", "__GNUC__", "PLATFORM_64BITS", "SE_IS_CSS", "SE_IS_HL2DM", "SE_IS_SDK2013"}


def sources(root):
    text = (Path(root) / "AMBuilder").read_text()
    ext = types.SimpleNamespace(name="sigsegv", exclude=["mods_debug", "mods_visualize", "mods_vgui"], optimize_mods_only=False)
    scope = {"Extension": ext}
    exec(text[:text.index("project = builder.LibraryProject")], scope)
    return sorted(set(scope["sourceFiles"]) - LINUX_ONLY)


def units(root):
    """sources() and every .cpp of this tree they #include on Windows, such as
    stub/__merge.cpp's. An SDK source such as collisionutils.cpp is not followed."""
    root = Path(root)
    found, pending = set(), list(sources(root))
    while pending:
        path = pending.pop()
        if path in found:
            continue
        found.add(path)
        text = preprocess((root / path).read_text(errors="replace"))
        for name in re.findall(r'^\s*#\s*include\s+"([^"]+\.cpp)"', text, re.M):
            for candidate in (str(Path(path).parent / name), f"src/{name}"):
                if (root / candidate).is_file():
                    pending.append(candidate)
                    break
    return sorted(found)


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
    """True or False for the conditions that decide a TF2 Windows build, None (kept) otherwise."""
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
    m = re.fullmatch(r"(!?)\s*defined\s+(\w+)", cond)
    if m and m.group(2) in DEFINED | UNDEFINED:
        return (m.group(2) in DEFINED) != bool(m.group(1))
    return None


if __name__ == "__main__":
    for f in sources(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]):
        print(f)
