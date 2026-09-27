#!/bin/bash
# The b0246f3 fault at sigsegv.ext.2.tf2.dll+0x7e27a is CBasePlayer::GetWearable
# reading m_hMyWearables[0] through 0xc1400000. Who calls it, and is there a
# console log of shard 0 anywhere in the run's artifacts.
set -u
RUN=36289640316
hdr=$(git config --get http.https://github.com/.extraheader 2>/dev/null | sed 's/^AUTHORIZATION: //I')
mkdir -p /tmp/sym && cd /tmp/sym
curl -sS -H "Authorization: $hdr" "https://api.github.com/repos/m-this/sigsegv-mvm-win/actions/runs/$RUN/artifacts" > arts.json
for name in symbols package-windows winbed heapcheck bed-1; do
	id=$(python3 -c "import json,sys;print(next(a['id'] for a in json.load(open('arts.json'))['artifacts'] if a['name']=='$name'))")
	curl -sSL -H "Authorization: $hdr" -o "$name.zip" "https://api.github.com/repos/m-this/sigsegv-mvm-win/actions/artifacts/$id/zip"
	mkdir -p "$name" && unzip -q -o "$name.zip" -d "$name"
done
echo "== files"; find winbed heapcheck bed-1 -type f | head -80
echo "== mentions of 7e27a or deathpour"; grep -rIl "7e27a\|technical_terror" winbed heapcheck bed-1 2>/dev/null | head
for f in $(grep -rIl "7e27a" winbed heapcheck bed-1 2>/dev/null | head -3); do echo "## $f"; grep -n -B5 -A40 "7e27a" "$f" | head -120; done
dll=$(find /tmp/sym/package-windows -iname 'sigsegv.ext.2.tf2.dll' | head -1)
pdb=$(find /tmp/sym/symbols -iname 'sigsegv.ext.2.tf2.pdb' | head -1)
sudo mkdir -p /home/runner/winport/winport-build && sudo cp "$pdb" /home/runner/winport/winport-build/ && sudo chmod a+r /home/runner/winport/winport-build/*.pdb
sym=/usr/bin/llvm-symbolizer-18
echo "== fault"; $sym --obj="$dll" --relative-address --inlines --demangle 0x7e27a
python3 - "$dll" > /tmp/sym/callers.txt <<'PY'
import sys, pefile
pe = pefile.PE(sys.argv[1])
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
want = 0x7e268
at = code.find(b"\xe8")
while at != -1:
    if at + 5 <= len(code):
        rel = int.from_bytes(code[at+1:at+5], "little", signed=True)
        if tv + at + 5 + rel == want: print(hex(tv + at + 5))
    at = code.find(b"\xe8", at + 1)
PY
echo "== $(wc -l < /tmp/sym/callers.txt) call sites of GetWearable, by return address"
while read -r a; do echo "-- $a"; $sym --obj="$dll" --relative-address --inlines --demangle "$a" | grep -v '^$' | paste -sd' ' | cut -c1-400; done < /tmp/sym/callers.txt
