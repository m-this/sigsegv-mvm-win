"""twin.py SYM...: Windows twin of a Linux function, by what the matched callers of it call"""
import json,pickle,sys,collections
m=json.load(open('/home/mathis/b3/matches.json'))
d=pickle.load(open('/home/mathis/b3/calls.pickle','rb'))
import pickle as pk
li=pk.load(open('/home/mathis/b3/lin.idx','rb'))
lin,win,names=d['lin'],d['win'],d['names']
matched_w={v['rva']:k for k,v in m.items() if isinstance(v.get('rva'),int)}
def lin_addr(sym):
    return li['by_name'].get(sym)
for sym in sys.argv[1:]:
    a=lin_addr(sym)
    if a is None: print(sym,'no linux addr'); continue
    callers=[c for c,t in lin.items() if a in t and c!=a]
    score=collections.Counter(); per={}
    used=0
    for c in callers:
        cn=names.get(c,'')
        # find the sym of caller c
        sc=None
        for k,v in li['by_name'].items():
            pass
        break
    # reverse map linux addr->sym (once)
    break
rev={v:k for k,v in li['by_name'].items()}
df=collections.Counter()
for f,t in win.items():
    for x in t: df[x]+=1
for sym in sys.argv[1:]:
    a=li['by_name'].get(sym)
    if a is None: print(sym,'no linux addr'); continue
    callers=[c for c,t in lin.items() if a in t and c!=a]
    score=collections.Counter(); n=0; tot=0
    for c in callers:
        s=rev.get(c)
        if s is None or s not in m or not isinstance(m[s].get('rva'),int): continue
        w=m[s]['rva']
        if w not in win: continue
        n+=1; tot+=lin[c][a]
        for t,cnt in win[w].items():
            if t in matched_w: continue
            score[t]+=1
    import math
    N=len(win)
    sc2={t:(c/n)*math.log(N/(1+df.get(t,0))) for t,c in score.items()} if n else {}
    print(f"== {sym}: {len(callers)} linux callers, {n} matched; linux call sites {tot}")
    for t,v in sorted(sc2.items(),key=lambda x:-x[1])[:6]: print(f"   {hex(t)} in {score[t]}/{n} callers, called by {df.get(t,0)} functions, score {v:.2f}")
