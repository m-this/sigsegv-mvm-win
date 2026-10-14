"""Score a Linux symbol against a Windows candidate on every independent signal.

A candidate address is only as good as the evidence for it, and a match record
carries whichever signal found it and no other. This recomputes the rest from
the binaries, so a proposal can be judged on several at once:

  start      is the address a function start at all;
  size       the ratio of the two function sizes. GCC and MSVC do not emit the
             same number of bytes, but they do not differ by seventy times
             either: Script_StringToFile is 133 bytes on Linux and 9,552 on
             Windows because the candidate is the caller that inlined it;
  strings    the literals the two reference, shared and each side's excess. A
             candidate mentioning many its twin never does is a bigger
             function that swallowed it;
  callees    how much of the Linux function's matched callee set it calls.

verdict() is the bar used in the sweep of 2026-09-19. It is not proof, and
nothing goes into the table on it alone: see status/20260919-sweep.
"""
import collections
import json
import pickle
import sys

sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent))
import matchfuncs as mf

class Scorer:
    def __init__(self, so, dll, matches_path, graphs_path):
        self.linux=mf.Linux(so); self.windows=mf.Windows(dll)
        self.matches=json.load(open(matches_path))
        self.lg,self.wg=pickle.load(open(graphs_path,'rb'))
        self.starts=set(self.windows.starts)
        self.fwd={self.linux.by_name[n]: m['rva']+self.windows.base
                  for n,m in self.matches.items() if n in self.linux.by_name}
        self.ls={}; self.ws={}
        for t,fs in self.linux.string_references().items():
            for f in fs: self.ls.setdefault(f,set()).add(t)
        for t,fs in self.windows.string_references().items():
            for f in fs: self.ws.setdefault(f,set()).add(t)
    def wsize(self,w):
        if w not in self.starts: return 0
        i=self.windows.starts.index(w)
        return (self.windows.starts[i+1]-w) if i+1<len(self.windows.starts) else 0
    def score(self, sym, rva):
        a=self.linux.by_name.get(sym)
        if a is None: return None
        w=rva+self.windows.base
        lsz=self.linux.functions.get(a,(0,0))[1]
        wsz=self.wsize(w)
        want=[t for t in set(self.lg.get(a,())) if t in self.fwd]
        called=set(self.wg.get(w,()))
        hit=sum(1 for t in want if self.fwd[t] in called)
        L=self.ls.get(a,set()); W=self.ws.get(w,set())
        return dict(start=w in self.starts, lsize=lsz, wsize=wsz,
                    ratio=(wsz/lsz) if lsz else 0,
                    callees_hit=hit, callees=len(want),
                    shared=len(L&W), linux_only=len(L-W), windows_only=len(W-L))

def verdict(s):
    """Accept only what several independent signals agree about."""
    if s is None or not s['start']: return False,'not a function start'
    if s['lsize'] and not (0.4 <= s['ratio'] <= 2.5):
        return False,f"size ratio {s['ratio']:.2f}"
    # A candidate referencing many strings its Linux twin does not is a bigger
    # function that swallowed it, which is what inlining looks like from here.
    if s['windows_only'] > max(3, 2*s['shared']):
        return False,f"{s['windows_only']} strings only on the Windows side"
    strong_strings = s['shared'] >= 2 and s['windows_only'] <= max(2, s['shared'])
    strong_callees = s['callees'] >= 4 and s['callees_hit']/s['callees'] >= 0.8
    if strong_strings and (s['callees'] == 0 or s['callees_hit']/s['callees'] >= 0.5):
        return True,'strings'
    if strong_callees and s['shared'] >= 1: return True,'strings+callees'
    if strong_callees and s['callees'] >= 6 and s['callees_hit']==s['callees']:
        return True,'callees'
    return False,'not enough agreement'
