"""Which names namegaps.py takes for address names, on gamedata small enough to read.

    python3 -m unittest tools/winport/test_namegaps.py
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import namegaps  # noqa: E402

# misc.txt:3399's shape: a symbol left without its closing quote, then the
# same line again with it, inside an addrs_group.
MISC = '''"Games"
{
	"#default"
	{
		"sigsegv"
		{
			"addrs_group"
			{
				"[common]"
				{
					type "sym"
					lib  "server"
				}
				"CEyeballBossIdle::OnStart" "_ZN16CEyeballBossIdle7OnStartEP12CEyeballBossP6ActionIS0_E
				"CEyeballBossIdle::OnStart" "_ZN16CEyeballBossIdle7OnStartEP12CEyeballBossP6ActionIS0_E"
				"CTeam::GetName" "_ZNK5CTeam7GetNameEv"
			}
			"addrs_group"
			{
				"[common]"
				{
					type "sym regex"
					lib  "engine"
				}
				// "VScriptRunScript [clone]" _Z16VScriptRunScriptPKcP9HSCRIPT__b
				"Host_ShowIPCCallCount [clone]" "_Z21Host_ShowIPCCallCountv\\\\.part\\\\..*"
			}
			"addrs"
			{
				"CTFPlayer::Spawn"
				{
					type "sym"
					sym  "_ZN9CTFPlayer5SpawnEv"
				}
			}
		}
	}
}
'''

# custom_attributes.txt's shape: quoted key-value pairs that name no address.
ATTRIBUTES = '''"items_game"
{
	"attributes"
	{
		"4000"
		{
			"name"	"parachute disabled"
			"attribute_class"	"parachute_disabled"
			"description_string"	"Parachute disabled"
			"description_format"	"value_is_additive"
			"effect_type"	"negative"
			"hidden"	"0"
			"stored_as_integer"	"0"
			"attribute_type"	"float"
		}
	}
}
'''


class DefinedNames(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        gamedata = Path(self.dir.name) / "gamedata/sigsegv"
        gamedata.mkdir(parents=True)
        (gamedata / "misc.txt").write_text(MISC)
        (gamedata / "custom_attributes.txt").write_text(ATTRIBUTES)
        (gamedata / "windows.txt").write_text('"Games" { "#default" { "sigsegv" { "addrs" { "Ignored" { type "fixed" } } } } }\n')
        self.names = namegaps.defined_names(Path(self.dir.name))

    def tearDown(self):
        self.dir.cleanup()

    def test_addresses_only(self):
        self.assertEqual(set(self.names), {
            "CEyeballBossIdle::OnStart",
            "CTeam::GetName",
            "Host_ShowIPCCallCount [clone]",
            "CTFPlayer::Spawn",
        })

    def test_unterminated_quote_ends_at_the_line(self):
        self.assertEqual(self.names["CTeam::GetName"], {"type": "sym", "lib": "server", "sym": "_ZNK5CTeam7GetNameEv"})
        self.assertEqual(self.names["Host_ShowIPCCallCount [clone]"]["lib"], "engine")

    def test_no_gamedata_keyword(self):
        for keyword in ("addrs", "addrs_group", "sym", "lib", "regex", "server", "sigsegv", "{", "}", "name", "attribute_class"):
            self.assertNotIn(keyword, self.names)


if __name__ == "__main__":
    unittest.main()
