"""mkcalls.py: build /home/mathis/b3/calls.pickle: Linux and Windows server direct-call graphs from lin.dis and win.dis"""
import re,pickle,collections
def lin():
    fn=None;calls=collections.defaultdict(collections.Counter);names={}
    hdr=re.compile(r'^([0-9a-f]+) <(.*)>:$')
    call=re.compile(r'^\s+[0-9a-f]+:\s+(?:call|jmp)\s+([0-9a-f]+) <')
    for l in open('/home/mathis/b3/lin.dis',errors='ignore'):
        m=hdr.match(l)
        if m: fn=int(m.group(1),16);names[fn]=m.group(2);continue
        if fn is None: continue
        m=call.match(l)
        if m: calls[fn][int(m.group(1),16)]+=1
    return dict(calls),names
def win():
    calls=collections.defaultdict(collections.Counter);prev_int3=True;fn=None
    ins=re.compile(r'^([0-9a-f]+):\s+(\S+)\s*(.*)$')
    for l in open('/home/mathis/b3/win.dis',errors='ignore'):
        m=ins.match(l.rstrip())
        if not m: continue
        a=int(m.group(1),16)-0x10000000;op=m.group(2)
        if op=='int3': prev_int3=True;continue
        if prev_int3: fn=a
        prev_int3=False
        if op in('call','jmp'):
            mm=re.match(r'0x1([0-9a-f]{7})\b',m.group(3))
            if mm: calls[fn][int(mm.group(1),16)]+=1
    return dict(calls)
lc,names=lin();wc=win()
pickle.dump({'lin':lc,'names':names,'win':wc},open('/home/mathis/b3/calls.pickle','wb'))
print(len(lc),len(wc))
