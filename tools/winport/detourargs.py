#!/usr/bin/env python3
"""Refuse a member detour or virtual hook whose parameters are not the function's.

A member detour on Windows is __thiscall: it pops its own arguments. Declared
with fewer parameters than the game passes, it pops too few, the caller's
stack is off by the difference, and the next `ret` lands on an argument.
Under Linux cdecl the caller pops and nothing shows, which is how
func_optimize.cpp's GetEntityForLoadoutSlot(int), for a function taking
(int, bool), shipped: on Windows it returned to eip=1, the bool.

    detourargs.py            from the repository root, or anywhere under it

Pairs every DETOUR_DECL_MEMBER with the MOD_ADD_DETOUR_MEMBER in the same file
that names its gamedata entry, reads that entry's Linux symbol from
gamedata/sigsegv, and compares parameter counts with the demangled symbol.
Exits 1 on any mismatch. Every entry is checked, resolved on Windows or not
yet, so resolving one cannot bring back a detour that was never checked.
"""

import re
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]


def split_params(text):
    out, depth, current = [], 0, ""
    for ch in text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        out.append(current.strip())
    return [p for p in out if p not in ("", "void")]


def macro_args(text, start):
    """The text between the parentheses opening at start, and where it ends."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i
    return None, start


def template_args(text, start):
    """The text between the angle brackets opening at start, and where it ends."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "<":
            depth += 1
        elif text[i] == ">":
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i
    return None, start


def tf2_only(text):
    """The text with the #else branch of every `#ifdef SE_IS_TF2` blanked, lines kept."""
    out, stack = [], []
    for line in text.split("\n"):
        s = line.strip()
        if s.startswith("#if"):
            stack.append(["SE_IS_TF2" in s and not s.startswith("#ifndef"), False])
        elif s.startswith("#else") and stack:
            stack[-1][1] = True
        elif s.startswith("#endif") and stack:
            stack.pop()
        out.append("" if any(tf2 and in_else for tf2, in_else in stack) else line)
    return "\n".join(out)


def main():
    symbol_of = {}
    for path in sorted((root / "gamedata/sigsegv").glob("*.txt")):
        table = path.read_text(errors="replace")
        for m in re.finditer(r'\n\s*"([^"]+)"\s*\n\s*\{[^{}]*?\bsym\s+"(_Z[^"]+)"', table):
            symbol_of.setdefault(m[1], m[2])

    wanted = []
    for path in sorted((root / "src").rglob("*.cpp")) + sorted((root / "src").rglob("*.h")):
        text = path.read_text(errors="replace")
        decls = {}
        for m in re.finditer(r"\b(?:DETOUR_DECL_MEMBER|VHOOK_DECL)\s*(?=\()", text):
            args, _ = macro_args(text, m.end())
            if args is None:
                continue
            parts = split_params(args)
            if len(parts) >= 2:
                decls.setdefault(parts[1], []).append((parts[2:], text.count("\n", 0, m.start()) + 1))
        # A virtual hook sits in a vtable slot with no pop check at load, so
        # its declaration is checked here or nowhere: MOD_ADD_VHOOK(name,
        # class, "Func") and MOD_ADD_VHOOK2(name, class, class, "Func").
        adds = [(m[1], m[2]) for m in re.finditer(r'\bMOD_ADD_DETOUR_MEMBER(?:_PRIORITY)?\s*\(\s*(\w+)\s*,\s*"([^"]+)"', text)]
        for m in re.finditer(r"\b(?:MOD_ADD_VHOOK\w*|CVirtualHook\w*)\s*(?=\()", text):
            args, _ = macro_args(text, m.end())
            if args is None:
                continue
            parts = split_params(args)
            cb = re.search(r"GET_VHOOK_CALLBACK\(\s*(\w+)\s*\)", args)
            names = [p.strip('"') for p in parts if re.fullmatch(r'"[A-Za-z_][\w:]*::~?\w+(?: \[\w+\])?"', p)]
            detour = cb[1] if cb else (parts[0] if parts and m[0].startswith("MOD_ADD") else None)
            if detour and names:
                adds.append((detour, names[-1]))
        for detour, name in adds:
            if name in symbol_of and detour in decls:
                for params, line in decls[detour]:
                    wanted.append((path.relative_to(root), line, detour, name, symbol_of[name], params))

    # Thunks: SigMod calling the game. A member thunk declared with fewer
    # parameters than the game's function pushes fewer than it pops, so the
    # caller's stack is short by the difference after every call. Linux's
    # caller pops and never shows it; GetEntityForLoadoutSlot(int) for the
    # game's (int, bool) was called from a Spawn path on every map load.
    for path in sorted((root / "src").rglob("*.cpp")):
        text = tf2_only(path.read_text(errors="replace"))
        for m in re.finditer(r"\b(?:MemberFuncThunk|MemberVFuncThunk)\s*<", text):
            args, end = template_args(text, m.end() - 1)
            if args is None:
                continue
            name = re.match(r'\s*[\w:]+\s*\(\s*(?:TypeName<\w+>\(\)\s*,\s*|"[^"]*"\s*,\s*)?"([^"]+)"\s*\)', text[end + 1:])
            if name is None or name[1].startswith("[client]") or name[1] not in symbol_of:
                continue
            params = [p.strip() for p in re.split(r",(?![^<>()]*[>)])", args)][2:]
            wanted.append((path.relative_to(root), text.count("\n", 0, m.start()) + 1, "thunk", name[1], symbol_of[name[1]], params))

    symbols = sorted({w[4] for w in wanted})
    plain = dict(zip(symbols, subprocess.run(["c++filt"], input="\n".join(symbols), capture_output=True, text=True, check=True).stdout.splitlines()))

    bad = 0
    for path, line, detour, name, symbol, params in wanted:
        demangled = plain.get(symbol, "")
        body = demangled[:-len(" const")] if demangled.endswith(" const") else demangled
        if not symbol.startswith("_ZN") or not body.endswith(")"):
            continue
        depth = 0
        for i in range(len(body) - 1, -1, -1):
            depth += body[i] == ")"
            depth -= body[i] == "("
            if depth == 0:
                break
        game = split_params(body[i + 1:-1])
        if "..." in game or len(game) == len(params):
            continue
        bad += 1
        print(f"{path}:{line}: {detour} takes {len(params)} parameters, {name} is {demangled}")
    print(f"{len(wanted)} member detours, virtual hooks and thunks checked, {bad} with the wrong number of parameters")
    sys.exit(1 if bad else 0)


main()
