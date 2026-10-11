"""loopback.py [windows.txt] [win.dis]: server.dll addresses a branch re-enters inside the first 5 bytes

A detour writes a 5-byte jmp over a function's entry. A loop that jumps back
to an instruction inside those bytes runs the middle of that jmp: every
address printed here can be read, but not detoured."""
import re, sys

table = sys.argv[1] if len(sys.argv) > 1 else "gamedata/sigsegv/windows.txt"
listing = sys.argv[2] if len(sys.argv) > 2 else "/home/mathis/b3/win.dis"
base = 0x10000000
names = {}
entry = re.compile(r'\t"([^"]+)"\n\t*\{\n\t*type  "fixed"\n\t*sym   "[^"]*"\n\t*addr  "(0x[0-9a-f]+)"\n\t*build "\d+"\n\t*lib   "server"')
for m in entry.finditer(open(table).read()):
    names[int(m.group(2), 16) + base] = m.group(1)
branch = re.compile(r'^([0-9a-f]+):\tj\w+\s+0x([0-9a-f]+)$')
for line in open(listing):
    m = branch.match(line)
    if not m:
        continue
    source, target = int(m.group(1), 16), int(m.group(2), 16)
    for into in range(1, 5):
        start = target - into
        if start in names and 0 < source - start < 0x4000:
            print(f"{names[start]} 0x{start - base:x}: 0x{source - base:x} jumps to +{into}")
