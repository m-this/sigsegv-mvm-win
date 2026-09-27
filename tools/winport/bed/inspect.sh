#!/bin/bash
# Every knownvtidx row the overload rule changes, keyed by class as well as name.
cd derived || exit 0
mkdir -p /tmp/oldmv && curl -sSfL -o /tmp/oldmv/matchvtables.py https://raw.githubusercontent.com/m-this/sigsegv-mvm-win/d94007d/tools/winport/matchvtables.py
(cd /tmp/oldmv && python3 matchvtables.py "$OLDPWD/linux-vtables" "$OLDPWD/win-vtables" "$OLDPWD/classified.json" > /dev/null) && cp /tmp/oldmv/winport_knownvtidx.txt old_knownvtidx.txt
python3 - <<'PY'
import re
from pathlib import Path
def rows(path):
    out = {}
    for m in re.finditer(r'"([^"]+)"\n\{\n\ttype +"func knownvtidx"\n\tvtable +"([^"]+)"\n\tidx +"(\d+)"\n\t// (\S+); linux \+0x([0-9a-f]+), windows (0x[0-9a-f]+)', Path(path).read_text()):
        out[(m.group(1), m.group(2))] = (int(m.group(3)), m.group(6))
    return out
old, new = rows("old_knownvtidx.txt"), rows("winport_knownvtidx.txt")
print(f"rows: old {len(old)}, new {len(new)}")
for key in sorted(set(old) | set(new)):
    if old.get(key) != new.get(key):
        print("CHANGED", key, old.get(key), "->", new.get(key))
PY
true
