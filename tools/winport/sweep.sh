#!/usr/bin/env bash
# Add scored candidates in small groups, keeping only the groups that still play.
#
#     tools/winport/sweep.sh candidates.json [group-size]
#
# Each group is added on top of everything kept so far, so one bad address
# costs its group rather than the whole set. A failing group is worth
# bisecting: two more runs name the address.
set -uo pipefail
ALL="$1"; SIZE="${2:-4}"
cd "$(dirname "$0")/../.."
total=$("${PYTHON:-$HOME/winport-deps/venv/bin/python}" -c "import json;print(len(json.load(open('$ALL'))))")
kept=0; dropped=0
for ((i=0; i<total; i+=SIZE)); do
	"${PYTHON:-$HOME/winport-deps/venv/bin/python}" - "$ALL" "$i" "$SIZE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); i=int(sys.argv[2]); n=int(sys.argv[3])
json.dump(d[i:i+n],open('/tmp/group.json','w'),indent=1)
print('group:', ', '.join(a['name'] for a in d[i:i+n]))
PY
	"$(dirname "$0")/addtest.sh" /tmp/group.json "group $i" >/tmp/group.out 2>&1
	if grep -q 'VERDICT PASS' /tmp/group.out; then
		kept=$((kept+SIZE)); echo "  PASS group $i"
		"${PYTHON:-$HOME/winport-deps/venv/bin/python}" -c "
import json,shutil;shutil.copy('tools/winport/overrides.json','/tmp/overrides-kept.json')"
	else
		dropped=$((dropped+SIZE)); echo "  FAIL group $i (reverted)"
	fi
done
echo "SWEEP DONE: kept about $kept, dropped about $dropped"
