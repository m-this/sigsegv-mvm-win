#!/bin/bash
# Symbolise sigsegv.ext.2.tf2.dll+0x7e27a of the Windows package run 36289640316
# (b0246f3), the fault on mvm_deathpour_rc1_int_technical_terror.
set -u
RUN=36289640316
RVA=0x7e27a
hdr=$(git config --get http.https://github.com/.extraheader 2>/dev/null | sed 's/^AUTHORIZATION: //I')
mkdir -p /tmp/sym && cd /tmp/sym
curl -sS -H "Authorization: $hdr" "https://api.github.com/repos/m-this/sigsegv-mvm-win/actions/runs/$RUN/artifacts" > arts.json
python3 -c "import json;[print(a['id'],a['name']) for a in json.load(open('arts.json')).get('artifacts',[])]" || head -c 400 arts.json
for name in symbols package-windows; do
	id=$(python3 -c "import json,sys;print(next(a['id'] for a in json.load(open('arts.json'))['artifacts'] if a['name']=='$name'))")
	curl -sSL -H "Authorization: $hdr" -o "$name.zip" "https://api.github.com/repos/m-this/sigsegv-mvm-win/actions/artifacts/$id/zip"
	mkdir -p "$name" && unzip -q -o "$name.zip" -d "$name" || { echo "no $name"; head -c 300 "$name.zip"; }
	( cd "$name" && for z in *.zip; do [ -f "$z" ] && unzip -q -o "$z"; done ) 2>/dev/null
done
find . -iname '*.dll' -o -iname '*.pdb' | xargs ls -la
dll=$(find . -iname 'sigsegv.ext.2.tf2.dll' | head -1)
pdb=$(find . -iname 'sigsegv.ext.2.tf2.pdb' | head -1)
echo "dll=$dll pdb=$pdb"
sym=$(command -v llvm-symbolizer-18 || command -v llvm-symbolizer || ls /usr/lib/llvm-*/bin/llvm-symbolizer 2>/dev/null | tail -1)
[ -n "$sym" ] || { sudo apt-get install -y -q llvm-18 > /dev/null 2>&1; sym=$(command -v llvm-symbolizer-18); }
echo "symbolizer: $sym"
for a in 0x7e27a 0x7e270 0x7e260 0x7e240 0x7e200; do
	echo "== $a"; "$sym" --obj="$dll" --relative-address --inlines --functions=linkage --demangle "$a" 2>&1 | head -30
	"$sym" --obj="$dll" --relative-address --inlines --demangle "$a" 2>&1 | head -30
done
cd - > /dev/null
python3 - "$dll" <<'PY'
import sys, pefile, capstone
pe = pefile.PE(sys.argv[1] if sys.argv[1].startswith('/') else '/tmp/sym/' + sys.argv[1])
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
rva = 0x7e27a
at = rva - tv
s = at
while s > 0 and not (code[s-1] == 0xCC and code[s-2] == 0xCC): s -= 1
print(f"function start guess {tv+s:#x}")
for i in md.disasm(code[s:at+0x80], base + tv + s):
    mark = "  <==" if i.address - base == rva else ""
    print(f"  {i.address-base:#x}  {i.mnemonic} {i.op_str}{mark}")
PY
dll=$(find /tmp/sym -iname 'sigsegv.ext.2.tf2.dll' | head -1)
pdb=$(find /tmp/sym -iname 'sigsegv.ext.2.tf2.pdb' | head -1)
pu=$(command -v llvm-pdbutil-18 || command -v llvm-pdbutil || ls /usr/lib/llvm-*/bin/llvm-pdbutil 2>/dev/null | tail -1)
if [ -n "$pdb" ] && [ -n "$pu" ]; then
	"$pu" dump --publics "$pdb" > /tmp/sym/publics.txt 2>&1
	python3 - <<'PY'
import re
rows = []
for l in open('/tmp/sym/publics.txt', errors='replace'):
    m = re.search(r'`(.*)`', l)
    if m: name = m.group(1); continue
    m = re.search(r'addr = (\d+):(\d+)', l)
    if m and 'name' in dir():
        rows.append((int(m.group(1)), int(m.group(2)), name))
# section 1 is .text at 0x1000
t = sorted((0x1000 + o, n) for s, o, n in rows if s == 1)
import bisect
for want in (0x7e27a,):
    k = bisect.bisect_right([a for a, _ in t], want) - 1
    for a, n in t[max(0, k-3):k+3]:
        print(f"  {a:#x} {n}{'   <== holds 0x7e27a' if a == t[k][0] else ''}")
PY
fi
