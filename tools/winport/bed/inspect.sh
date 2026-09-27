#!/bin/bash
for c in CTFBot CTFPlayer; do
  echo "== win $c"; head -4 derived/win-vtables/$c.txt 2>&1
  echo "== linux $c"; head -4 derived/linux-vtables/$c.txt 2>&1
done
grep -n 'CTFBot' tools/winport/knownvtidx.generated.txt | head -5
