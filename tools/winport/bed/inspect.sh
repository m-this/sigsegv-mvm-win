#!/bin/bash
# Five detours refused on their pops: each Windows body whole, with every ret,
# the bytes after it, its direct callers with the pushes before each call, and
# the Linux body beside it.
python3 - <<'PY'
import re, struct, subprocess, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def body(rva, n=500):
    va = base + rva; out = []
    for i in md.disasm(code[va - tva:va - tva + 0x3000], va):
        if i.mnemonic == "int3": break
        out.append(i)
        if len(out) >= n: break
    return out
def show(insns):
    for i in insns:
        op = i.op_str
        if i.mnemonic in ("call", "jmp") and op.startswith("0x"): op = f"0x{int(op, 16) - base:x}"
        print(f"    {i.address - base:x}: {i.mnemonic} {op}")
def callers(rva, before=10, after=3):
    va = base + rva; hits = []
    for m in re.finditer(b"\xe8", code):
        at = m.start()
        if at + 5 > len(code): break
        if tva + at + 5 + struct.unpack_from("<i", code, at + 1)[0] == va: hits.append(tva + at)
    for h in hits[:6]:
        print(f"  caller at 0x{h - base:x}")
        pre = []
        for back in range(0x60, 0, -1):
            ins = list(md.disasm(code[h - back - tva:h + 0x20 - tva], h - back))
            if any(i.address == h for i in ins): pre = ins; break
        k = [j for j, i in enumerate(pre) if i.address == h][0] if pre else 0
        show(pre[max(0, k - before):k + after + 1])
    print(f"  {len(hits)} direct callers")
    # also immediates holding its VA (a think function's pointer, a vtable)
    refs = [m.start() for m in re.finditer(re.escape(struct.pack("<I", va)), code)]
    print(f"  VA as an immediate in .text at: {[hex(tva + r - base) for r in refs[:8]]}")
for name, rva in [("ApplyAttributeFloatWrapper", 0x39dc30), ("PlayerEvent_Upgraded", 0x5e0500),
                  ("ValidTargetPlayer", 0x4cab30), ("TeleporterThink", 0x4d1a70), ("CTFBaseRocket::Destroy", 0x6395c0)]:
    ins = body(rva)
    end = ins[-1].address + ins[-1].size - base if ins else rva
    print(f"=== windows {name} 0x{rva:x}, {len(ins)} insns to the first int3, ends 0x{end:x}")
    print(f"  rets: {[(hex(i.address - base), i.op_str) for i in ins if i.mnemonic == 'ret']}")
    print(f"  bytes after: {code[base + end - tva:base + end - tva + 16].hex()}")
    show(ins)
    callers(rva)
PY
echo "=== CTFBaseRocket vtables around Destroy"
python3 - <<'PY'
import re, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def rows(path):
    out = []
    for l in open(path):
        if l.startswith("// vtable") and "offset 0x0000" not in l: break
        m = re.match(r'\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)', l)
        if m: out.append((int(m.group(2), 16), m.group(3).strip()))
    return out
def head(va):
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in list(md.disasm(code[va - tva:va - tva + 0x30], va))[:6])
lin = rows("derived/linux-vtables/CTFBaseRocket.txt"); win = rows("derived/win-vtables/CTFBaseRocket.txt")
for s in range(len(lin)):
    if "Destroy" in lin[s][1]: print(f"  linux slot {s}: {lin[s][1]}")
for s in range(max(0, 226), min(len(lin), 244)): print(f"  linux {s}: {lin[s][1]}")
for s in range(226, min(len(win), 240)): print(f"  windows {s}: 0x{win[s][0] - base:x}  {head(win[s][0])}")
PY
echo "=== linux bodies"
so=game-linux/tf/bin/server_srv.so
for sym in _ZN17CAttributeManager26ApplyAttributeFloatWrapperEfP11CBaseEntity8string_tP10CUtlVectorIS1_10CUtlMemoryIS1_iEE \
           _ZN19CMannVsMachineStats20PlayerEvent_UpgradedEP9CTFPlayertthsb \
           _ZN16CObjectSentrygun17ValidTargetPlayerEP9CTFPlayerRK6VectorS4_ \
           _ZN17CObjectTeleporter15TeleporterThinkEv \
           _ZN13CTFBaseRocket7DestroyEbb; do
  line=$(nm -S "$so" 2>/dev/null | grep " $sym\$" | head -1)
  [ -z "$line" ] && line=$(nm -D -S "$so" 2>/dev/null | grep " $sym\$" | head -1)
  echo "--- $sym: $line"
  [ -z "$line" ] && continue
  addr=$((16#$(echo $line | cut -d' ' -f1))); size=$((16#$(echo $line | cut -d' ' -f2)))
  objdump -d --no-show-raw-insn -C --start-address=$addr --stop-address=$((addr + size)) "$so" | tail -n +7 | head -400
done
