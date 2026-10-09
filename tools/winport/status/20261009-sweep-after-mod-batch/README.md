# The bed sweep after the mod batch

PRs #7 to #20 landed on main one at a time, each with a green Address table
run, and the table went from 1323 to 1443 entries. The CI bed then played
every SigMod mission on Windows in survey mode, where a call SigMod has no
address for is logged and returns zero instead of ending the server.

Two sweeps, because the first measured a defect the batch had introduced:

- 37959506551 on main `24612609` (all fourteen PRs): cancelled after four of
  the eight shards, 34 of their 41 missions died on one fault, below;
- 37977150267 on main `a2e15882`, the same plus the fix for that fault
  (`41b168df`) and `CTFPlayer::ClearDisguiseWeaponList` (`a2e15882`).

The numbers below are the second sweep. `matrix.txt` is its raw matrix,
`matrix-20261006.txt` the bed's last sweep before the batch (37455429768, tag
20261006 at `7826839c`), `matrix-24612609.txt` the cancelled one.

## Against the earlier sweeps

| | 2026-09-19 (Wine, 3 maps) | 2026-10-06 (CI bed, before) | 2026-10-09 (CI bed, after) |
| --- | ---: | ---: | ---: |
| entries in `windows.txt` | | 1323 | 1443 |
| addresses resolved, of listed | 1245 of 2769 | 1606 of 2785 | 1781 of 2786 |
| mods OK / FAILED | 10 / 22 | 94 / 20 | 94 / 20 |
| failed detours, of detours | | 505 of 1505 | 317 of 1494 |
| missions played | 3 | 95 | 95 |
| wave 1 passed | 3 | 94 | 92 |
| every wave played passed | | 87 | 84 |
| server deaths | 1 map refused | 0 | 0 |
| unresolved functions reached | 0 | 1 | 5 |

The two CI columns are the same bed, the same 95 missions and the same build,
11087207. The 2026-09-19 column is the Wine bed on build 24245063 with fewer
mods enabled, so only its direction compares. Its one refused map,
`mvm_skeleclipse_b7a`, plays all five of its missions now.

Of the addresses, 174 went from FAIL to resolved and none went the other way.
The mission-facing mods lost most of their failed detours:

| mod | failed detours before | after |
| --- | ---: | ---: |
| `Pop:PopMgr_Extensions` | 10 of 126 | 1 of 125 |
| `Attr:Custom_Attributes` | 122 of 298 | 52 of 298 |
| `Pop:ECAttr_Extensions` | 13 of 54 | 2 of 49 |
| `Pop:TFBot_Extensions` | 13 of 66 | 3 of 66 |
| `Pop:Tank_Extensions` | 7 of 33 | 4 of 32 |
| `Etc:Mapentity_Additions` | 10 of 67 | 2 of 67 |
| `Perf:Extra_Player_Slots` (disabled on the bed) | 27 of 58 | 0 of 56 |
| `Pop:PointTemplates`, `Pop:Wave_Extensions`, `MvM:Robot_Limit`, `Util:Lua`, `MvM:Extended_Upgrades`, `MvM:Upgrade_Disallow` | 12 | 0 |

`NextBotPlayer<CTFPlayer>::ReleaseCrouchButton` (#19) resolves and its detour
is still refused, as a trivial body MSVC may have merged with others.

## Fault signatures

The second sweep has none: every shard ran its missions on one server start.

The cancelled sweep had one, for all 34 deaths:

    fault 0xc0000005 at sigsegv.ext.2.tf2.dll+0x1e50d7 touching 0xbf800010
      std::vector<CustomVariable>::empty
      <- CBaseEntity::GetCustomVariableBool<"ispassiveaction">   extraentitydata.h:490
      <- Mod::Pop::TFBot_Extensions::Detour_CTFBot_OnWeaponFired  tfbot_extensions.cpp:2292
      <- server.dll, Custom_Attributes' CTFWeaponBaseMelee::Swing, ItemPostFrame,
         Util:Lua's PlayerRunCommand, PhysicsSimulate

#17 resolved `CTFBot::OnWeaponFired` at 0x55f3c0 and its evidence says the body
is the entry of CTFBot's INextBot table: `this` is the INextBot subobject, the
bot plus 0x2668. TFBot_Extensions' detour used `this` as the bot, read its
custom variables from 0x2668 bytes too far, got 0xbf800000 (-1.0f) as a
pointer and faulted on the first weapon fired. The detour on
`NextBotPlayer<CTFPlayer>::Update`, the same table, read the team number the
same wrong way. `TFBotFromNextBot` in `stub/tfbot.h` now gets the bot through
`INextBot::GetEntity` in both, Windows only.

## What a mission reaches unresolved

Survey mode logs these and carries on. Without it, each one ends the server.

| function | reached from | missions | address from |
| --- | --- | --- | --- |
| `CTFBotMainAction::SelectCloserThreat` | ECAttr_Extensions' `SelectMoreDangerousThreatInternal` detour, for a bot with melee threat prioritization | `mvm_kelly_rc1b_adv_mobocracy`, `mvm_chateau_rc3_adv_remedic`, `mvm_condemned_b3_exp_trespasser` | #19 |
| `CBaseCombatWeapon::CheckReload`, no vtable index | Custom_Attributes' `CTFWeaponBase::ItemHolsterFrame` detour, for passive reload | `mvm_terrorlict_final1c5_adv_accursed_aggrievocation`, `mvm_robotfactory_b30_exp_enduring_exceptions` | #15 |
| `CBaseCombatWeapon::SecondaryAttack`, no vtable index | Unintended_Class_Weapon_Improvements' `CTFPlayer::DoClassSpecialSkill` detour, a non-demo with a sticky launcher | `mvm_condemned_b3_exp_trespasser_remaster` | before the batch; the mission timed out on wave 1 before and gets that far now |
| `UTIL_SetSize` | not named by the log: `Attr:CustomProjectileModel_Precache` is the one caller loaded at boot, and a mission can turn on `Etc:Player_Bullet_Bounding_Fix` or the `AI:My_Nextbot` mods | `mvm_kelly_rc1b_adv_mobocracy` | before the batch |
| `CBaseEntityOutput::DeleteAllElements` | PopMgr_Extensions' `CPopulationManager::ResetMap` detour, at the first map load | every shard | before the batch, also in the 2026-10-06 sweep |

## Missions

Eleven failed, all on the 15-minute wall-clock limit of a wave, with no fault.
Seven of them failed before too. The changes:

- `mvm_condemned_b3_exp_trespasser_remaster` passes; it timed out on wave 1.
- `mvm_creepside_b2_adv_dismal_devilry` stops on wave 1 with no enemy spawned
  and 77 left; it reached wave 6 before. It ran in shard 3, see below.
- `mvm_hideout_b3_adv_wet_warfare` w1, `mvm_mannhattan_adv_scorched_skies` w1,
  `mvm_ghost_town_adv_horrorsome_happenings` w7 and
  `mvm_oilrig_rc5d_adv_waters_of_wrath` w8 time out with bots spawned and
  killed and the wave's remaining count stuck (82, 83, 132, 24); they passed
  before. Why the count stays up is not read yet.

## Other things the sweep showed

- In shard 3 only, `Pop:TFBot_Extensions` loaded FAILED: its virtual hook on
  `CBaseEntity::KeyValue` for `CObjectTeleporter` found no vtable on that
  server start. The hook is upstream's and no other shard, in either sweep,
  failed it. Shard 3 played its eleven missions without the mod. Without it
  the game's own parser refuses every TFBot block that carries `NoIdleSound`,
  `SpawnTemplate`, `action` or `FireInput` (822 `TFBotSpawner: Unknown field`
  lines in shard 3, none in the others), which is why `dismal_devilry` spawned
  nothing on wave 1.
  The cause is `RTTI::PreLoad`. It finds a vtable by scanning `.rdata` for the
  class's locator address and takes it only when exactly one word matches. The
  scan reads the loaded image, strings included, so at some `server.dll` bases
  a string equals the address: at 0x73e10000 the locator of `CObjectTeleporter`
  is 0x74757074, "tput" of "output", and 76 words of `.rdata` hold it. Re-running the scan
  over the shipped `server.dll` relocated to every 64 KiB base from 0x50000000
  to 0x7a000000, 868 of 10752 bases lose at least one class and 12 lose
  `CObjectTeleporter`. The bed does not log the base, so which one shard 3
  drew is not known. The scan now keeps only a match followed by code (and a
  locator whose class descriptor is in `.rdata`).
- Shard 3's private memory reached 1621 MB, against 878 MB before, during
  `mvm_oilrig_rc5d_adv_waters_of_wrath` wave 8 (1337 bots spawned in the 15
  minutes), mostly 16 MB allocations. No other shard rose by more than 30 MB.
- The heapcheck job's `sig_list_addrs` came back empty in both sweeps, so its
  `addrs:` and `coverage: addresses` lines read 0. The server prints the list,
  and it now takes 11 s against 6.8 s before, past `rcon.exe`'s 10 s timeout
  (`launcher/internal/rcon/rcon.go` in tf2-archipelago). The counts above come
  from that printed list in `winbed-1.out`, which matches the rcon reply line
  for line on the 2026-10-06 run.
