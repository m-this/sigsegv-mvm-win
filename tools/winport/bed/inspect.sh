#!/bin/bash
# What SigMod said at load about the detours b0246f3 changed, in a bed shard of
# its run (36289640316) and of 8bacdd5's (36286641441).
set -u
hdr=$(git config --get http.https://github.com/.extraheader 2>/dev/null | sed 's/^AUTHORIZATION: //I')
mkdir -p /tmp/beds && cd /tmp/beds
for RUN in 36289640316 36286641441; do
	curl -sS -H "Authorization: $hdr" "https://api.github.com/repos/m-this/sigsegv-mvm-win/actions/runs/$RUN/artifacts" > arts-$RUN.json
	id=$(python3 -c "import json;print(next(a['id'] for a in json.load(open('arts-$RUN.json'))['artifacts'] if a['name']=='bed-1'))")
	curl -sSL -H "Authorization: $hdr" -o "$RUN.zip" "https://api.github.com/repos/m-this/sigsegv-mvm-win/actions/artifacts/$id/zip"
	mkdir -p "$RUN" && unzip -q -o "$RUN.zip" -d "$RUN"
	echo "######## run $RUN"
	cat $RUN/console-previous.log $RUN/console.log $RUN/consoles/*.log 2>/dev/null > $RUN/all.txt
	grep -a -i -E "refused|pop(s|ped)? |Destroy|ApplyAttributeFloatWrapper|PlayerEvent_Upgraded|RemoveDisguiseWeapon|IsAbleToSee|PlayerSolidMask|FindTarget|Teleporter(Think|Send)|CTFGameRules \[C1\]|CTFGameRules::CTFGameRules|VScriptServerInit|InitGrenade|FVisible|AimHeadTowards" $RUN/all.txt | sed 's/^L [0-9/ :-]*//' | sort | uniq -c | sort -rn | head -60
	echo "-- fault lines"; grep -a -i -E "fault 0x|EBP chain|^ +[0-9a-f]{8} " $RUN/all.txt | head -20
done
