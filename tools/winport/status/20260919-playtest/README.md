# The port playing, on three maps, with everything loaded

`playtest.sh` run against the table as committed: 104 overrides, 931
addresses. Every run has the tf2-archipelago plugin, the MvM defender bots and
SigMod loaded together.

| map | mission | wave 1 | addresses OK | unresolved calls |
| --- | --- | --- | ---: | ---: |
| `mvm_decoy` | `mvm_decoy` (Valve) | yes | 1207 | 0 |
| `mvm_deathpour_rc1` | `mvm_deathpour_rc1_exp_blackout` (community, SigMod, expert) | yes | 1206 | 0 |
| `mvm_mannworks` | `mvm_mannworks` (Valve) | yes | 1206 | 0 |

"unresolved calls" counts `SigMod: called unresolved function`, which ends the
server when it happens. None did.

The address count moves by one between runs because two datamaps resolve
through a runtime scan over the entities a map has spawned.

## What the archipelago plugin gained

`winsig.py` cut Windows byte signatures for 13 functions this port had already
located, and they went into the plugin's own gamedata. Three of its mechanics
stopped reporting themselves broken on Windows:

    A refused mission file will not be reported: CPopulationManager::Parse ...
    Faulty Calibration sniper deviation disabled: FX_FireBullets ...
    Mental robot cloak disabled: stock RemoveInvisibility hook is unavailable

What is still off needs field offsets rather than signatures, which is
apw-5g4.16's work: Bot Surge's support fillers want the
`CWaveSpawnPopulator::m_*` offsets, and Make it Count wants
`CObjectDispenser::DispenseAmmo`, for which no Windows address is known yet.
