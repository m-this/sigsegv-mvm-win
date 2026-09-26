#!/bin/bash
# GetConditionDuration, PlaySpecificSequence and RemoveCustomAttribute: the
# Windows functions shaped like the Linux bodies.
python3 - <<'PY'
import re, collections, capstone, pefile
from elftools.elf.elffile import ELFFile

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
def wstart(rva):
    at = rva - tv
    while at > 0 and not (code[at-1] in (0xCC, 0x90) and code[at-2] in (0xCC, 0x90)): at -= 1
    return tv + at
wg = collections.defaultdict(set)
at = code.find(b"\xe8")
while at != -1:
    src = tv + at; dst = src + 5 + int.from_bytes(code[at+1:at+5], "little", signed=True)
    if tv <= dst < tv + len(code): wg[dst].add(src)
    at = code.find(b"\xe8", at + 1)
def ins(start, limit=400):
    out = []
    for n, i in enumerate(md.disasm(code[start-tv:start-tv+6000], base + start)):
        out.append(i)
        if i.mnemonic == "int3" or n >= limit: break
    return out
def wdis(start, limit=250):
    print(f"== windows {start:#x}")
    for i in ins(start, limit):
        line = f"  {i.address-base:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"): line += f"    -> {int(i.op_str, 16)-base:#x}"
        print(line)

# Burn and HasAmmo, whole
wdis(0x51a2c0, 140)
wdis(0x1e1b50, 80)
wdis(0x6365d0, 30)

# GetConditionDuration: a caller of InCond indexing a 20 byte array
print("== InCond callers indexing by cond*20")
for f in sorted({wstart(s) for s in wg[0x5234e0]}):
    body = ins(f, 60)
    txt = [f"{i.mnemonic} {i.op_str}" for i in body]
    if any(re.match(r"lea \w+, \[(\w+) \+ \1\*4\]", t) for t in txt) and len(body) < 60:
        print(f"  {f:#x} n={len(body)}: " + "; ".join(txt))
# AddCond's head, where m_ConditionData is written
wdis(0x5196a0, 120)

# PlaySpecificSequence: DoAnimationEvent with event 0x13 and 0x15 in one function
print("== DoAnimationEvent callers pushing 0x13 and 0x15")
for f in sorted({wstart(s) for s in wg[0x4e8420]}):
    txt = [f"{i.mnemonic} {i.op_str}" for i in ins(f, 120)]
    if "push 0x13" in txt and "push 0x15" in txt:
        print(f"  {f:#x}"); wdis(f, 60)

# RemoveCustomAttribute: the callers of AddCustomAttribute and what else they call
print("== AddCustomAttribute callers")
for f in sorted({wstart(s) for s in wg[0x4e0340]}):
    cs = [int(i.op_str, 16) - base for i in ins(f) if i.mnemonic == "call" and i.op_str.startswith("0x")]
    print(f"  {f:#x}: calls " + ", ".join(f"{c:#x}" for c in cs))
for cls in ("CTriggerAddOrRemoveTFPlayerAttributes", "CTFLunchBox"):
    try:
        print(f"== {cls} win vtable size", sum(1 for l in open(f"derived/win-vtables/{cls}.txt") if l.startswith("+")))
    except Exception as e: print(cls, e)
PY
