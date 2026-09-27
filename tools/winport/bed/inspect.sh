#!/bin/bash
# The keys CSmokeStack::KeyValue compares, on both sides.
python3 - <<'PY'
import pefile, subprocess
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
img = pe.get_memory_mapped_image()
def wstr(va):
    rva = va - 0x10000000
    return img[rva:img.index(b"\0", rva)].decode("latin-1")
print("windows 0x1083df8c:", repr(wstr(0x1083df8c)), " 0x107994b8:", repr(wstr(0x107994b8)))
out = subprocess.run(["readelf", "-S", "-W", "game-linux/tf/bin/server_srv.so"], capture_output=True, text=True).stdout
data = open("game-linux/tf/bin/server_srv.so", "rb").read()
secs = []
for line in out.splitlines():
    p = line.replace("[ ", "[").split()
    if len(p) > 5 and p[0].startswith("["):
        try:
            secs.append((int(p[3], 16), int(p[4], 16), int(p[5], 16)))
        except ValueError:
            pass
def lstr(va):
    for a, off, size in secs:
        if a and a <= va < a + size:
            o = off + va - a
            return data[o:data.index(b"\0", o)].decode("latin-1")
for va in (0x11e7b63, 0x1264c75, 0x1264c81, 0x1264c13, 0x12024e3, 0x123cd6a):
    print(f"linux {va:#x}:", repr(lstr(va)))
PY
true
