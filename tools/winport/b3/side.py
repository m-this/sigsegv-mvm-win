"""side.py SYM [N]: Linux and Windows bodies of a matched function, side by side in order, calls annotated"""
import json,re,subprocess,sys,collections,pickle
m=json.load(open('/home/mathis/b3/matches.json'))
rev={}
for s,v in m.items():
    if isinstance(v.get('rva'),int): rev.setdefault(v['rva'],s)
sym=sys.argv[1]; N=int(sys.argv[2]) if len(sys.argv)>2 else 26
rva=m[sym]['rva']
lin=subprocess.run(['/home/mathis/b3/bin/lf',sym],capture_output=True,text=True).stdout.split('\n')
print('== LINUX',sym)
n=0
for l in lin[2:]:
    mm=re.match(r'\s*[0-9a-f]+:\s+(.*)',l)
    if not mm: continue
    s=re.sub(r'\s*<[^>]*\+0x[0-9a-f]+>','',mm.group(1))
    s=re.sub(r'<(.{0,50})[^>]*>',r'<\1>',s)
    print('  ',s); n+=1
    if n>=N: break
print('== WINDOWS',hex(rva))
out=subprocess.run(['/home/mathis/b3/venv/bin/python','/home/mathis/b3/bin/wd.py',hex(rva)[2:],'0x400'],capture_output=True,text=True).stdout.split('\n')
n=0
for l in out:
    if 'int3' in l: break
    mm=re.search(r'(call|jmp)\s+0x1([0-9a-f]{7})\b',l)
    if mm and int(mm.group(2),16) in rev and '<' not in l:
        l+=' <'+rev[int(mm.group(2),16)][:50]+'>'
    print('  ',l.split(': ',1)[-1] if ': ' in l else l); n+=1
    if n>=N: break
