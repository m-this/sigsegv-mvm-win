"""Which files the Windows package compiles, on a tree small enough to read.

    python3 -m unittest tools/winport/test_shipped.py
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import shipped  # noqa: E402

AMBUILDER = '''sourceFiles = ['src/main.cpp']
if 'mods_debug' not in Extension.exclude:
  sourceFiles += ['src/mod/debug/tool.cpp']
project = builder.LibraryProject(extName)
'''

FILES = {
    "src/main.cpp": '#include "stub/__merge.cpp"\n#include "util/misc.h"\n',
    "src/stub/__merge.cpp": '#include "stub/a.cpp"\n#if !defined _WINDOWS\n#include "stub/linux.cpp"\n#endif\n// #include "stub/commented.cpp"\n#include "stub/a.cpp"\n',
    "src/stub/a.cpp": '#include "stub/b.cpp"\n#include "collisionutils.cpp"\n',
    "src/stub/b.cpp": '#include "stub/__merge.cpp"\n',
    "src/stub/linux.cpp": "",
    "src/stub/commented.cpp": "",
    "src/mod/debug/tool.cpp": '#include "stub/debug.cpp"\n',
    "src/stub/debug.cpp": "",
}


class Units(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        (root / "AMBuilder").write_text(AMBUILDER)
        for path, text in FILES.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text)
        self.root = root

    def tearDown(self):
        self.dir.cleanup()

    def test_sources_are_the_build_list(self):
        self.assertEqual(shipped.sources(self.root), ["src/main.cpp"])

    def test_units_follow_included_sources(self):
        self.assertEqual(shipped.units(self.root), [
            "src/main.cpp",
            "src/stub/__merge.cpp",
            "src/stub/a.cpp",
            "src/stub/b.cpp",
        ])


if __name__ == "__main__":
    unittest.main()
