"""MSVC's overload order, on dumps small enough to read.

    python3 -m unittest tools/winport/test_matchvtables.py
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import matchvtables as mv  # noqa: E402


def dump(directory, cls, *slots):
    rows = [cls, "", "// vtable at 0x00001000 offset 0x0000"]
    # An address is its slot index unless the slot says otherwise, so a body
    # is folded only where a test folds it.
    slots = [s if isinstance(s, tuple) else (0x100 + i, s) for i, s in enumerate(slots)]
    rows += [f"+0x{i * 4:04x}:  {a:08x}  {s}" for i, (a, s) in enumerate(slots)]
    (Path(directory) / f"{cls}.txt").write_text("\n".join(rows) + "\n")


class Names(unittest.TestCase):
    def test_split(self):
        self.assertEqual(mv.split_name("CTFPlayer::KeyValue(char const*, float)"), ("CTFPlayer", "KeyValue"))
        self.assertEqual(mv.split_name("CUtlVector<A::B>::Foo(int) const"), ("CUtlVector<A::B>", "Foo"))
        self.assertEqual(mv.split_name("A<B>::operator<(A<B> const&) const"), ("A<B>", "operator<"))
        self.assertEqual(mv.method("CFoo::~CFoo()"), "~")

    def test_key_drops_the_class(self):
        self.assertEqual(mv.slot_key("CTFPlayer::KeyValue(char const*, float)"),
                         mv.slot_key("CBaseEntity::KeyValue(char const*, float)"))
        self.assertIsNone(mv.slot_key("__cxa_pure_virtual"))


class Order(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = self.dir.name
        dump(d, "CBase",
             "CBase::~CBase()", "CBase::~CBase()",
             "CBase::Spawn()",
             "CBase::KeyValue(char const*, char const*)",
             "CBase::KeyValue(char const*, float)",
             "CBase::Think()",
             "CBase::KeyValue(char const*, Vector const&)",
             "CBase::Touch(CBase*)")
        # Overrides one KeyValue and adds a Touch overload and two new names.
        dump(d, "CDerived",
             "CDerived::~CDerived()", "CDerived::~CDerived()",
             "CBase::Spawn()",
             "CDerived::KeyValue(char const*, char const*)",
             "CBase::KeyValue(char const*, float)",
             "CBase::Think()",
             "CBase::KeyValue(char const*, Vector const&)",
             "CDerived::Touch(CBase*)",
             "CDerived::Walk()",
             "CDerived::Run()",
             "CDerived::Touch(int)")
        # IGameMovement and CGameMovement, cut down. An interface whose slots
        # are all pure matches any table that starts with a destructor, so
        # these two get a directory of their own.
        self.movedir = tempfile.TemporaryDirectory()
        d = self.movedir.name
        dump(d, "IMove",
             "IMove::~IMove()", "IMove::~IMove()",
             "__cxa_pure_virtual", "__cxa_pure_virtual", "__cxa_pure_virtual")
        dump(d, "CMove",
             "CMove::~CMove()", "CMove::~CMove()",
             "CMove::Process()",
             "CMove::Mins(bool) const",
             "CMove::Maxs(bool) const",
             "CMove::Trace()",
             "CMove::SolidMask(bool)",
             "CMove::Mins() const",
             "CMove::Maxs() const",
             "CMove::Friction()")
        self.corpus = mv.Corpus(self.dir.name)
        self.movement = mv.Corpus(self.movedir.name)

    def tearDown(self):
        self.dir.cleanup()
        self.movedir.cleanup()

    def names(self, cls, corpus=None):
        corpus = corpus or self.corpus
        slots = corpus.tables[cls]
        return [slots[i] for i in corpus.order(cls)]

    def test_overloads_group_at_the_first_and_reverse(self):
        self.assertEqual(self.names("CBase")[2:], [
            "CBase::Spawn()",
            "CBase::KeyValue(char const*, Vector const&)",
            "CBase::KeyValue(char const*, float)",
            "CBase::KeyValue(char const*, char const*)",
            "CBase::Think()",
            "CBase::Touch(CBase*)",
        ])

    def test_a_derived_class_keeps_its_base_layout(self):
        self.assertEqual(self.corpus.parent("CDerived"), "CBase")
        got = self.names("CDerived")
        self.assertEqual(got[3:6], [
            "CBase::KeyValue(char const*, Vector const&)",
            "CBase::KeyValue(char const*, float)",
            "CDerived::KeyValue(char const*, char const*)",
        ])
        # Touch(int) is new here and CDerived overrides Touch(CBase*), which
        # it may declare anywhere: the group stays put and is reported.
        self.assertEqual(got[8:], ["CDerived::Walk()", "CDerived::Run()", "CDerived::Touch(int)"])
        self.assertEqual(self.corpus.ambiguous["CDerived"], ["Touch"])

    def test_declared_first_moves_new_overloads_up(self):
        mv.DECLARED_FIRST["CMove"] = ("Mins", "Maxs")
        self.addCleanup(mv.DECLARED_FIRST.pop, "CMove")
        self.assertEqual(self.movement.parent("CMove"), "IMove")
        self.assertEqual(self.names("CMove", self.movement)[5:], [
            "CMove::Mins() const",
            "CMove::Maxs() const",
            "CMove::Trace()",
            "CMove::SolidMask(bool)",
            "CMove::Friction()",
        ])

    def test_a_folded_body_groups_with_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            dump(d, "CFold",
                 "CFold::~CFold()", "CFold::~CFold()",
                 "CFold::Enemy()",
                 (0x900, "CFold::Enemy() const"),
                 "CFold::Think()",
                 (0x900, "CFold::Enemy() const"))
            corpus = mv.Corpus(d)
            # Slot 3 and 5 are one `return NULL` under one of its names, so
            # neither is an Enemy overload as far as the order goes.
            self.assertEqual(corpus.order("CFold"), [0, 1, 2, 3, 4, 5])

    def test_align_collapses_the_destructor(self):
        how, aligned = mv.align(self.corpus.tables["CBase"], list(range(7)), self.corpus.order("CBase"))
        self.assertEqual(how, "collapse")
        self.assertEqual(aligned.index("CBase::KeyValue(char const*, char const*)"), 4)
        self.assertEqual(mv.align(self.corpus.tables["CBase"], list(range(5)))[0], None)


if __name__ == "__main__":
    unittest.main()
