"""The PE fields binaries.py reads, on headers small enough to write by hand.

    python3 -m unittest tools/winport/test_binaries.py
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import binaries  # noqa: E402


def header(stamp, size, magic=0x10B, e_lfanew=0x100):
    out = bytearray(0x400)
    out[:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, e_lfanew)
    out[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHI", out, e_lfanew + 4, 0x14C, 5, stamp)
    struct.pack_into("<H", out, e_lfanew + 24, magic)
    struct.pack_into("<I", out, e_lfanew + 24 + 56, size)
    return bytes(out)


class Identity(unittest.TestCase):
    def test_reads_the_stamp_and_the_size(self):
        self.assertEqual(binaries.identity(header(0x68F0A1B2, 0xCB6000)),
                         {"TimeDateStamp": "0x68f0a1b2", "SizeOfImage": "0xcb6000"})

    def test_another_link_is_another_identity(self):
        self.assertNotEqual(binaries.identity(header(0x68F0A1B2, 0xCB6000)),
                            binaries.identity(header(0x68F0A1B3, 0xCB6000)))
        self.assertNotEqual(binaries.identity(header(0x68F0A1B2, 0xCB6000)),
                            binaries.identity(header(0x68F0A1B2, 0xCB4000)))

    def test_refuses_what_is_not_a_pe32_image(self):
        with self.assertRaises(ValueError):
            binaries.identity(b"\x7fELF" + header(1, 1)[4:])
        with self.assertRaises(ValueError):
            binaries.identity(header(1, 1)[:0x100])
        with self.assertRaises(ValueError):
            binaries.identity(header(1, 1, magic=0x20B))


if __name__ == "__main__":
    unittest.main()
