"""verify_rej.py SYM...: for rejected structural matches, compare callee sets (Linux callees matched to Windows rvas vs the Windows function's direct callees)."""
import json,re,subprocess,sys,collections
m=json.load(open('/home/mathis/b3/matches.json'))
rev=collections.defaultdict(list)
for s,v in m.items():
    if isinstance(v.get('rva'),int): rev[v['rva']].append(s)
import pickle
li=pickle.load(open('/home/mathis/b3/lin.idx','rb'))
by_addr={a:n for n,a in li['by_name'].items()}
def lin_callees(sym):
    a=li['by_name'][sym]
    out=subprocess.run(['/home/mathis/b3/bin/lf',sym],capture_output=True,text=True).stdout
    cs=set()
    for l in out.split('\n'):
        mm=re.search(r'(call|jmp)\s+([0-9a-f]+) <',l)
        if mm: cs.add(int(mm.group(2),16))
    return {by_addr.get(c,hex(c)) for c in cs if c!=a}
def win_callees(rva):
    out=subprocess.run(['/home/mathis/b3/venv/bin/python','/home/mathis/b3/bin/wd.py',hex(rva)[2:],'0x800'],capture_output=True,text=True).stdout.split('\n')
    cs=set();size=0
    for l in out:
        if 'int3' in l: break
        size+=1
        mm=re.search(r'(call|jmp)\s+0x1([0-9a-f]{7})\b',l)
        if mm:
            t=int(mm.group(2),16)
            if t!=rva: cs.add(t)
    return cs,size
for sym in sys.argv[1:]:
    rva=m[sym]['rva']
    lc=lin_callees(sym)
    wc,size=win_callees(rva)
    lm={c:m[c]['rva'] for c in lc if c in m and isinstance(m[c].get('rva'),int)}
    hit=[c for c,r in lm.items() if r in wc]
    miss=[c for c,r in lm.items() if r not in wc]
    print(f"{sym[:60]:60} rva {hex(rva)} winsz {size} linCallees {len(lc)} matched {len(lm)} hit {len(hit)} miss {len(miss)} {[x[:40] for x in miss[:3]]}")
