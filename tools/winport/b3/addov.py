"""addov.py [-e] KEY RVA|bad WHY [name=X] [vtidx=N]: add or replace an overrides.json entry (-e: lib engine)"""
import json, sys
import subprocess
P = subprocess.run(["git","rev-parse","--show-toplevel"],capture_output=True,text=True).stdout.strip()+"/tools/winport/overrides.json"
a = sys.argv[1:]
lib = None
if a[0] == "-e":
    lib = "engine"; a = a[1:]
key, rva, why, *rest = a
o = json.load(open(P))
if rva == "bad":
    e = {"bad": True, "why": why}
else:
    e = {}
    if lib: e["lib"] = lib
    for r in rest:
        k, v = r.split("=", 1)
        if k == "name": e["name"] = v
    e["rva"] = rva; e["build"] = "11087207"
    for r in rest:
        k, v = r.split("=", 1)
        if k == "vtidx": e["vtidx"] = int(v)
    e["why"] = why
if lib and rva == "bad": e = {"lib": lib, **e}
o[key] = e
open(P, "w").write(json.dumps(o, indent=1) + "\n")
print(key, e)
