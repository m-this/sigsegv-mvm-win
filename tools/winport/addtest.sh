#!/usr/bin/env bash
# Add a subset of scored candidates to overrides.json, rebuild windows.txt and
# play a map. A run that does not reach wave 1 with no unresolved calls is
# reverted, table and overrides both, so a wrong address costs one run.
#
#     tools/winport/addtest.sh candidates.json "label" [map]
#
# candidates.json is what score.py accepted: name, symbol, rva, via, why and
# the score. See status/20260919-sweep for why nothing goes in without this.
set -uo pipefail
SUBSET="$1"; LABEL="$2"; MAP="${3:-mvm_decoy}"
cd "$(dirname "$0")/../.."
cp tools/winport/overrides.json /tmp/overrides-prev.json
"${PYTHON:-$HOME/winport-deps/venv/bin/python}" - "$SUBSET" <<'PY'
import json,sys
ov=json.load(open('tools/winport/overrides.json'))
n=0
for a in json.load(open(sys.argv[1])):
    if a['symbol'] in ov: continue
    s=a['score']
    ov[a['symbol']]={"rva":hex(a['rva']),
      "why":(f"{a['via']}, agreed by {a['why']}: {s['shared']} shared string(s), "
             f"{s['callees_hit']}/{s['callees']} matched callees, windows/linux size "
             f"{s['wsize']}/{s['lsize']}")}
    n+=1
json.dump(ov,open('tools/winport/overrides.json','w'),indent=1,sort_keys=True)
print(f'added {n}, overrides now {len(ov)}')
PY
"${PYTHON:-$HOME/winport-deps/venv/bin/python}" tools/winport/emitgamedata.py /tmp/matchfuncs5.json 10828683 /tmp/datamaps.json tools/winport/knownvtidx.generated.txt > /tmp/windows-try.txt 2>/dev/null
echo "table blocks: $(grep -cE '^\s+\"[A-Za-z_]' /tmp/windows-try.txt)"
cp /tmp/windows-try.txt ~/tf2-win-server/tf/addons/sourcemod/gamedata/sigsegv/windows.txt
OUT=/tmp/addtest WAIT=400 tools/winport/playtest.sh "$MAP" > /tmp/addtest-run.txt 2>&1
cat /tmp/addtest-run.txt
if grep -q 'waves started 1' /tmp/addtest-run.txt && grep -q 'server alive  yes' /tmp/addtest-run.txt \
   && [ "$(sed -n 's/^unresolved calls //p' /tmp/addtest-run.txt)" = "0" ]; then
	echo "VERDICT PASS $LABEL"
else
	echo "VERDICT FAIL $LABEL"
	cp /tmp/overrides-prev.json tools/winport/overrides.json
	"${PYTHON:-$HOME/winport-deps/venv/bin/python}" tools/winport/emitgamedata.py /tmp/matchfuncs5.json 10828683 /tmp/datamaps.json tools/winport/knownvtidx.generated.txt > gamedata/sigsegv/windows.txt 2>/dev/null
	cp gamedata/sigsegv/windows.txt ~/tf2-win-server/tf/addons/sourcemod/gamedata/sigsegv/windows.txt
fi
