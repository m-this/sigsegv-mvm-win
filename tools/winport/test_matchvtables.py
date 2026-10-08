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
        # CGameMovement, cut down, and IGameMovement, which has no table of
        # its own in the dump: its three virtuals end at slot 5.
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
        for table, value in ((mv.DECLARED_FIRST, ("Mins", "Maxs")), (mv.MISSING_BASES, 5)):
            table["CMove"] = value
            self.addCleanup(table.pop, "CMove")

    def tearDown(self):
        self.dir.cleanup()

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

    def test_an_interface_is_no_base(self):
        # IMove is all pure and would start any table with a destructor.
        self.assertIsNone(self.corpus.parent("CMove"))
        self.assertEqual(self.corpus.parent("CBase"), None)

    def test_declared_first_moves_new_overloads_up(self):
        self.assertEqual(self.names("CMove"), [
            "CMove::~CMove()", "CMove::~CMove()",
            "CMove::Process()",
            "CMove::Mins(bool) const",
            "CMove::Maxs(bool) const",
            "CMove::Mins() const",
            "CMove::Maxs() const",
            "CMove::Trace()",
            "CMove::SolidMask(bool)",
            "CMove::Friction()",
        ])

    def test_without_the_boundary_the_runs_merge(self):
        mv.MISSING_BASES.pop("CMove")
        mv.DECLARED_FIRST.pop("CMove")
        self.addCleanup(mv.MISSING_BASES.__setitem__, "CMove", 5)
        self.addCleanup(mv.DECLARED_FIRST.__setitem__, "CMove", ("Mins", "Maxs"))
        self.assertEqual(self.names("CMove", mv.Corpus(self.dir.name))[3:7], [
            "CMove::Mins() const", "CMove::Mins(bool) const",
            "CMove::Maxs() const", "CMove::Maxs(bool) const",
        ])

    def test_a_folded_body_groups_with_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            dump(d, "CFold",
                 "CFold::~CFold()", "CFold::~CFold()",
                 "CFold::Walk()",
                 (0x900, "CFold::Enemy() const"),
                 "CFold::Think()",
                 (0x900, "CFold::Enemy() const"))
            corpus = mv.Corpus(d)
            # Slot 3 and 5 are one `return NULL` under one of its names, and
            # nothing else in the run is called Enemy: neither groups.
            self.assertEqual(corpus.order("CFold"), [0, 1, 2, 3, 4, 5])

    def test_align_collapses_the_destructor(self):
        how, aligned = mv.align(self.corpus.tables["CBase"], list(range(7)), self.corpus.order("CBase"))
        self.assertEqual(how, "collapse")
        self.assertEqual(aligned.index("CBase::KeyValue(char const*, char const*)"), 4)
        self.assertEqual(mv.align(self.corpus.tables["CBase"], list(range(5)))[0], None)


class Interfaces(unittest.TestCase):
    """What MSVC leaves out of the primary table: an override of a virtual a
    secondary base declares. Itanium keeps it there and puts a thunk to it in
    the secondary table."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        rows = [
            "CPlayer", "", "// vtable at 0x00001000 offset 0x0000",
            "+0x0000:  00000100  CPlayer::~CPlayer()",
            "+0x0004:  00000101  CPlayer::~CPlayer()",
            "+0x0008:  00000102  CPlayer::Spawn()",
            "+0x000c:  00000103  CPlayer::GetAttributes()",
            "+0x0010:  00000104  CPlayer::Reapply()",
            "+0x0014:  00000105  CPlayer::Think()",
            "",
            "// vtable at 0x00001000 offset 0x0020",
            "+0x0000:  00000200  non-virtual thunk to CPlayer::GetAttributes()",
            "+0x0004:  00000201  non-virtual thunk to CPlayer::Reapply()",
            "+0x0008:  00000202  non-virtual thunk to CPlayer::~CPlayer()",
        ]
        (Path(self.dir.name) / "CPlayer.txt").write_text("\n".join(rows) + "\n")
        self.corpus = mv.Corpus(self.dir.name, interface_drop=True)

    def test_thunk_targets_are_read_from_the_secondary_tables(self):
        self.assertEqual(
            mv.read_linux_thunks(Path(self.dir.name) / "CPlayer.txt"),
            {"CPlayer::GetAttributes()", "CPlayer::Reapply()", "CPlayer::~CPlayer()"})

    def test_an_interface_override_has_no_primary_slot_and_a_destructor_stays(self):
        slots = self.corpus.tables["CPlayer"]
        self.assertEqual([slots[i] for i in self.corpus.order("CPlayer")], [
            "CPlayer::~CPlayer()", "CPlayer::~CPlayer()", "CPlayer::Spawn()", "CPlayer::Think()"])
        how, aligned = mv.align(slots, [1, 2, 3], self.corpus.order("CPlayer"))
        self.assertEqual((how, aligned), ("collapse", ["CPlayer::~CPlayer()", "CPlayer::Spawn()", "CPlayer::Think()"]))

    def test_the_drop_is_off_unless_asked_for(self):
        plain = mv.Corpus(self.dir.name)
        self.assertEqual(plain.order("CPlayer"), list(range(6)))

    def test_a_hand_read_address_has_to_agree(self):
        aligned = ["CPlayer::~CPlayer()", "CPlayer::Spawn()", "CPlayer::Think()"]
        windows = [0x10000100, 0x10000102, 0x10000105]
        verified = {"CPlayer::Spawn()": (0x102, None), "CPlayer::Think()": (0x105, 2)}
        self.assertEqual(mv.check_anchors(aligned, windows, verified), (2, []))
        verified = {"CPlayer::Spawn()": (0x105, None), "CPlayer::Think()": (0x105, 1)}
        agree, disagree = mv.check_anchors(aligned, windows, verified)
        self.assertEqual(agree, 0)
        self.assertEqual([d[:2] for d in disagree], [("CPlayer::Spawn()", 1), ("CPlayer::Think()", 2)])

    def test_a_signature_in_the_table_twice_anchors_nothing(self):
        aligned = ["CPlayer::Spawn()", "CPlayer::Spawn()"]
        windows = [0x10000100, 0x10000100]
        self.assertEqual(mv.check_anchors(aligned, windows, {"CPlayer::Spawn()": (0x999, None)}), (0, []))

    def test_a_destructor_anchors_nothing(self):
        self.assertEqual(mv.check_anchors(["CPlayer::~CPlayer()"], [0x10000100], {"CPlayer::~CPlayer()": (0x999, None)}), (0, []))


if __name__ == "__main__":
    unittest.main()
