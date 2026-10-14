#!/usr/bin/env python3
"""Find each class's datamap in server.dll, by the route the runtime scan takes.

A datamap_t holds a pointer to its class name at +8, and the class's
GetDataDescMap is `mov eax, <datamap>; ret`. So: the one place in .rdata
holding the class name, the places in .data pointing at it, and the one of
those a GetDataDescMap returns.

    datamaps.py server.dll gamedata/sigsegv/datamaps.txt > datamaps.json
"""

import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import matchfuncs as mf  # noqa: E402

DATA_CLASS_NAME = 8

windows = mf.Windows(sys.argv[1])
names = re.findall(r'^\s*"([A-Za-z_][A-Za-z0-9_]*)"\s+"(_Z\S+)"\s*$', open(sys.argv[2]).read(), re.M)

sections = {s.Name.rstrip(b"\0").decode(): (windows.base + s.VirtualAddress, s.get_data()) for s in windows.pe.sections}
rdata_base, rdata = sections[".rdata"]
data_base, data = sections[".data"]

out, ambiguous, missing = {}, [], []
for class_name, symbol in names:
    raw = class_name.encode() + b"\0"
    strings = [rdata_base + i for i in range(len(rdata)) if rdata.startswith(raw, i) and (i == 0 or rdata[i - 1] == 0)]
    if len(strings) != 1:
        (ambiguous if strings else missing).append(class_name)
        continue
    found = []
    for at in [data_base + i for i in range(0, len(data) - 4, 4) if data[i:i + 4] == struct.pack("<I", strings[0])]:
        datamap = at - DATA_CLASS_NAME
        if windows.text_bytes.find(b"\xb8" + struct.pack("<I", datamap) + b"\xc3") >= 0:
            found.append(datamap)
    if len(found) == 1:
        out[class_name] = {"sym": symbol, "rva": found[0] - windows.base}
    else:
        ambiguous.append(class_name)

json.dump(out, sys.stdout, indent=1)
print(f"{len(out)} datamaps; {len(ambiguous)} ambiguous; {len(missing)} without a class name string", file=sys.stderr)
print("  " + " ".join(ambiguous[:12]), file=sys.stderr)
