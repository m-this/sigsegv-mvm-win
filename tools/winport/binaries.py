#!/usr/bin/env python3
"""Which Windows binaries the address table reads, and how to tell one build of each from another.

    binaries.py GAME_DIR

Every fixed address in gamedata/sigsegv/windows.txt is an RVA into one of
LIBS. A Valve update that leaves all of them alone (11185272 and 11191711
moved only the content depot) leaves every address right, whatever
ServerVersion says. The identity of a binary is the TimeDateStamp of its PE
file header and the SizeOfImage of its optional header: the loader maps both
into memory with the image, so the extension reads them at the base it adds
the RVAs to, without opening the file. The linker writes both on every link.

Prints {lib: {"path", "TimeDateStamp", "SizeOfImage"}} as JSON, for
emitgamedata.py to put in the table and the Address table job in table.json.
"""

import json
import struct
import sys
from pathlib import Path

LIBS = {
    "server": "tf/bin/server.dll",
    "engine": "bin/engine.dll",
    "dedicated": "bin/dedicated.dll",
    "soundemittersystem": "bin/SoundEmitterSystem.dll",
    "tier0": "bin/tier0.dll",
    "vscript": "bin/vscript.dll",
}

HEADER_BYTES_MAX = 4096


def identity(header):
    """TimeDateStamp and SizeOfImage from the first bytes of a 32-bit PE image."""
    if header[:2] != b"MZ":
        raise ValueError("no MZ header")
    (e_lfanew,) = struct.unpack_from("<I", header, 0x3C)
    if e_lfanew + 24 + 60 > len(header) or header[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("no PE header")
    (time_date_stamp,) = struct.unpack_from("<I", header, e_lfanew + 4 + 4)
    optional = e_lfanew + 4 + 20
    (magic,) = struct.unpack_from("<H", header, optional)
    if magic != 0x10B:
        raise ValueError(f"optional header magic {magic:#x}, not PE32")
    (size_of_image,) = struct.unpack_from("<I", header, optional + 56)
    return {"TimeDateStamp": f"{time_date_stamp:#010x}", "SizeOfImage": f"{size_of_image:#x}"}


def identities(game_dir):
    out = {}
    for lib, rel in LIBS.items():
        with open(Path(game_dir) / rel, "rb") as f:
            out[lib] = {"path": rel, **identity(f.read(HEADER_BYTES_MAX))}
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(json.dumps(identities(sys.argv[1]), indent=1))


if __name__ == "__main__":
    main()
