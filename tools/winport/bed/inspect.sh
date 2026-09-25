#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
# TheNavMesh: unresolved on Windows, so every nav query SigMod makes runs on null.
python3 -c "import json; print('matched:', json.load(open('derived/matches.json')).get('TheNavMesh'))"
python3 tools/winport/whereis.py game-linux/tf/bin/server_srv.so game-windows/tf/bin/server.dll derived/matches.json TheNavMesh 2>&1 | tail -40
