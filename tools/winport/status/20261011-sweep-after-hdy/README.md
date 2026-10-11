# The bed sweeps while closing the mod gaps

Branch `winport-mod-hdy`, four CI bed runs on the same 95 missions and the same
build, 11087207. Each run found one fault the previous one hid.

| run | head | server deaths | missions failed | cause of the deaths |
| --- | --- | ---: | ---: | --- |
| 38083420280 | `fb0c8332` | 7 of 8 shards | 10 of 13 per shard | `CTFBot::PushRequiredWeapon` had no address, so the unmatched `PopRequiredWeapon` took the stack count to -1 and `EquipRequiredWeapon` read element -2 |
| 38097792901 | `c148ad94` | 7 of 8 boots | all | `CTFPlayer::PrecacheMvM` loops back to its third byte, inside the detour's 5-byte jmp |
| 38129638188 | `96371a30` | 3 missions | 13 of 95 | below |
| 38134245758 | `d7e95f5a` | 0 | 8 of 95 | none |

## What each fault was

- `PrecacheMvM` (0x507d20): a branch at 0x507d5a jumps to +3. Func_Optimize now
  hooks its one caller, `CTFGameRules::Precache` (0x4988f0), and runs the Rome
  promo precache after it on an `mvm_` map. `tools/winport/b3/loopback.py`
  lists the table addresses a branch re-enters in their first five bytes;
  this is the only one.
- `TFInventoryManager()` is inline in server.dll. The thunk had no address and
  returned null; `GetBaseItemForClass` read `this+0x34`. The singleton at
  0xa89250 is now the global `g_TFInventoryManager`.
- `CTFMedigunShield::Create` was matched to 0x61ad50, a `CWeaponMedigun`
  member with `Create` inlined (thiscall on the medigun, no argument). The
  detour took the medigun as the player and faulted on the first shield. The
  address is now turned away.
- Inline in server.dll, written from the Linux bodies: `CTFPlayerShared::
  IsLoserStateStunned`, `CTFNavArea::AddPotentiallyVisibleActor`.
- Addresses added: `CAI_BaseNPC::GetActivityID`, `CBaseServer::RunFrame`
  and `CModelLoader::FlushDynamicModels` (engine), the `modelloader` global.
- Slots added, read off the anchors of each table: `CBaseEntity::Spawn` 24,
  `CCurrencyPack::AffectedByRadiusCollection` 238, `CBaseObject::IsHostileUpgrade`
  361, `CBaseCombatWeapon::GetShootSound` 338.

## What is left

Eight missions time out on the 15-minute wall-clock limit of a wave, with no
fault: `sludge_b6_int_logging_dreadwood` w3, `terrorlict_final1c5_adv_accursed_
aggrievocation` w6, `creepside_b2_adv_dismal_devilry` w6, `creepside_b2_adv_
dust_to_dust` w5, `rottenburg_adv_marathon` w4, `spybase_rc8_exp_waters_of_a_
robot_regime` w6, `condemned_b3_exp_trespasser_remaster` w1 and `villa_b13f_adv_
forgotten` w6.

`sig_wave_dump` (now with the spawn points of each unfinished wave spawn) shows
three shapes:

- spybase `waters_of_a_robot_regime` w6: the stuck squad and limited-support
  wave spawns are SPAWNING with `spawned=0`, `result=0`, and every entry of their
  `Where` is `disabled=1` (`spawnbot_chief_demo`, `spawnbot_emp` to `emp5`,
  `spawnbot`). `FindSpawnLocation` is right to find none; what enables them
  (a map output, an input) did not run. The read of `m_bDisabled` (0x388 in the
  function, Linux 0x3a0) is the game's own.
- one robot alive that the bed never kills, on a team it cannot reach: marathon
  w4 waits on `w4e` for a RED bot at 1 health, dust_to_dust w5 for RED giants,
  villa w6 for a Samurai Demo, trespasser_remaster for a WAVE3-3 bot and an
  `eyeball_boss` on team 5.
- trespasser_remaster's pop holds over a hundred wave spawns in its first wave;
  its PENDING ones read garbage in `m_countSpawnedSoFar` (83886082) where the
  mod made them with no spawn count.

Not understood yet:

- `mvm_kelly_rc1b_adv_mobocracy` died in `sdkhooks.ext` once (+0x5981, reading
  4) under a `cbasenpc.ext` call; it passed in the last run.
- `mvm_autumnull_rc2_adv_dynamic_disaster` stopped the engine on
  `UTIL_SetModel: not precached: sapper_placement.mdl`; it passed in the last run.
- `tf2attributes.smx` fails to load on Windows (`Could not initialize call to
  CEconItemSchema::GetAttributeDefinitionByName`), and with it
  `tf2_archipelago` and `tf2_defenderbots`. That is SourceMod's gamedata, not
  SigMod's.

Still unported on purpose or for want of a standalone body: SendProp_Optimize,
YER_Unnerf, the inline-only Custom_Attributes functions (BCanBurnEntityThisFrame,
IsAllowedToInitiateTauntWithPartner, Energy_Recharge), Weapon_Shoot's
MaybeDrawRailgunBeam and OnOwnerKillEaterEvent_Batched, Vehicle_Fix, the
throwable `Create` functions, and about 95 thunks no mission reaches.
