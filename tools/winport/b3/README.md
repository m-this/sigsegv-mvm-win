# Scripts used to read server.dll against server_srv.so

These are the tools the address overrides in `../overrides.json` were made
with. They expect the working layout the port was done in, a directory
(`/home/mathis/b3`) holding:

- `game-linux/` and `game-windows/`: the two server installs (build 11087207)
- `lin.dis`, `win.dis`: objdump listings of `server_srv.so` and `server.dll`
- `lin.idx`: `{by_name, strs}` of the Linux image (see `bin/idx.py` there)
- `matches.json`: the output of `../matchfuncs.py`
- `win-vtables/`: `../dumpvtables.py`'s dump of `server.dll`

| script | what it does |
| --- | --- |
| `mkcalls.py` | builds `calls.pickle`, the direct-call graph of both images |
| `twin.py SYM...` | ranks the Windows callees that the matched callers of a Linux function share |
| `side.py SYM [N]` | prints a matched pair of bodies one after the other, Windows calls named by their Linux match |
| `verify_rej.py SYM...` | compares the callee sets of a structural match the emitter held back |
| `hexat.py RVA [LEN] [DLL]` | bytes at an RVA |
| `chkpat.py` | checks an extractor's byte pattern against `server.dll` and prints the value it reads |
| `addov.py [-e] KEY RVA\|bad WHY [name=X] [vtidx=N]` | adds an entry to `overrides.json` |
| `winext.py FILE NAME TYPE 'HEX with ??' FN MIN MAX OFFSET [ADJUST]` | writes a Windows byte-pattern extractor into a stub in place of `IExtractStub` |

A pattern an extractor looks for has to match exactly once in the range
`[function + min, function + max + length)`; `chkpat.py` prints every match
offset so a second hit shows before the bed does.
