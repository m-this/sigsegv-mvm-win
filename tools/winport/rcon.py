#!/usr/bin/env python3
"""Source RCON, dependency-free, for reading the Wine bed.

    RCON_HOST=192.168.50.133 RCON_PORT=27016 tools/winport/rcon.py sig_list_addrs

srcds under Wine binds rcon on the machine's LAN address, not loopback, and
takes the next port up when 27015 is already held: read the "Network: IP"
line in tf/console.log for both.
"""
import os
import socket, struct, sys, time
def pkt(i, t, body): b = body.encode() + b"\0\0"; return struct.pack("<iii", len(b) + 8, i, t) + b
def rd(s):
    hdr = s.recv(4); n = struct.unpack("<i", hdr)[0]; d = b""
    while len(d) < n: d += s.recv(n - len(d))
    i, t = struct.unpack("<ii", d[:8]); return i, t, d[8:-2].decode(errors="replace")
def run(host, port, pw, cmd, wait=1.5):
    s = socket.create_connection((host, port), timeout=10); s.sendall(pkt(1, 3, pw)); rd(s)
    s.sendall(pkt(2, 2, cmd)); s.sendall(pkt(3, 0, "")); out = ""
    s.settimeout(wait)
    try:
        while True:
            i, t, body = rd(s)
            if i == 3: break
            out += body
    except socket.timeout: pass
    s.close(); return out
if __name__ == "__main__":
    print(run(os.environ.get("RCON_HOST", "127.0.0.1"), int(os.environ.get("RCON_PORT", "27015")), os.environ.get("RCON_PASSWORD", "winport"), " ".join(sys.argv[1:])))
