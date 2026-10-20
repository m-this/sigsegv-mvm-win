# Windows coverage of SigMod mods and addresses

Measured on 2026-10-20 against TF2 ServerVersion 11138802, `mfe/feat/winport-parity`. Static: it reads the code and `gamedata/sigsegv/windows.txt`, not a bed run. `tools/winport/modgaps.py` is the base of the mod count (detours and virtual hooks only) and `tools/winport/namegaps.py` that of the address-name count, both with `--shipped` for what the Windows package compiles (`tools/winport/shipped.py`). The bed's `sig_list_mods` remains the truth for what actually loads: on main's last bed run (2026-10-18) the only FAILED mods were `Perf:SendProp_Optimize` and `Perf::Virtual_Call_Optimize`, of the 20 in `status/20261009-sweep-after-mod-batch/`; the first is now left out of the package and the second is ported.

## How it works

- Linux resolves each name by symbol from `server_srv.so`. Windows `server.dll` is stripped, so `windows.txt` is loaded first and holds a `fixed` RVA per name (`CSigsegvGameConf::NameTaken` drops later blocks under the same name). It is derived: `matchfuncs.py`/`matchvtables.py` pair Linux and Windows functions, `tools/winport/overrides.json` (hand entries keyed by Linux symbol, each with `build`, `why`, or `bad`) wins over the matches, `emitgamedata.py` writes the table, `carry.py`/`rebase.py` move overrides to a new build, `checktable.py` and `dupes.py` guard it. Entries for another build are ignored, and `SDK_OnLoad` refuses to load on a build the table is not for.
- Some names need no table entry: `func knownvtidx` and `.?AV` vtable slots, `func ebpprologue`, `datamap`, `convar` and `src/addr/*.cpp` classes resolve at run time on Windows (`FindAddrWin`). This file counts them as resolved; whether each does on a given build only a bed run says.
- `IMod::InvokeLoad` on Windows loads a mod without its failed detours; a failed patch or virtual hook fails the whole mod, and `Toggle` then keeps it off.
- The Windows package compiles AMBuilder's list without the `mods_debug`, `mods_visualize` and `mods_vgui` groups, as upstream's Linux packages do (`autoconfig.sh`), and without the sources in `shipped.py`'s `LINUX_ONLY`, each argued below. `_WINDOWS` guards inside mods swap individual detours for Windows equivalents or leave out one that has nothing to hook on Windows. Mods the bed lists as DISABLED are loaded but off until a convar or popfile key turns them on.

## Totals

| Status | Mods | main before (d7e6eea2) |
| --- | ---: | ---: |
| In the Windows package, every detour and virtual hook has an address | 182 | 180 |
| In the Windows package, server-side detours or hooks without an address | 0 | 4 |
| In the Windows package, only client-side addresses missing (nothing to hook on a dedicated server) | 11 | 11 |
| Left out of the Windows package on purpose, argued below | 4 | 2 |
| Debug, Visualize and VGUI tools (in no package), every address resolved | 74 | 74 |
| Debug and Visualize tools with server-side gaps | 13 | 13 |
| Debug tools with only client-side gaps | 2 | 2 |
| Compiled out on both platforms | 23 | 23 |
| All SigMod mods (`IMod`/`CModule` names) | 309 | 309 |

The four server-side gaps on main were `MvM:MedigunShield_Damage`, `Util:Overlay_Send`, `Util:Vehicle_Fix` and `Perf:SendProp_Optimize`. The first three are ported; `SendProp_Optimize` and `Perf::Virtual_Call_Optimize_Inline_Virtuals` join `Etc:Workshop_Map_Fix` and `Perf::CSS_Bot_Vision_Optimize` outside the package. Every one of the 13 Debug and Visualize tools with a gap has at least one detour that is inlined on Windows, only exists as a GCC clone, has no symbol on Linux either, or has not been located; the section below says which.

Address names, from `tools/winport/namegaps.py`. In the Windows package: 1,343 named in the compiled sources, 1,066 with a `windows.txt` entry, 183 resolved at run time, 4 recorded `bad`, 24 client-side and **66** with no Windows entry (main: 1,351, 1,066, 183, 7, 24, 71, counted with the same `shipped.py`). Over all of `src/`: 2,213 named, 1,517 table, 195 run time, 45 bad, 38 client, 418 missing (main: 2,212, 1,513, 195, 45, 38, 421). A missing name only matters when its thunk is called: several of the 66 sit in patch classes or thunks no mod registers on Windows.

## Debug and Visualize tools with unresolved addresses

`bad`: read by hand, no body of its own on 11117211 (the table below says where it went). `refused`: located, but the detour guard refuses it. `clone`: a GCC `.part` or `.isra` clone, whose arguments travel in registers (`__gcc_regcall`) and which MSVC has no counterpart of. `open`: not located.

- `Debug:CTFBotProxy` (2 of 4): `CTFBotProxy::CTFBotProxy [C1]` (bad: inline in the entity factory's `Create`), `CEventQueue::AddEvent [EventQueuePrioritizedEvent_t *]` (open: a sorted insert with no direct caller on Linux either, so nothing to anchor it by)
- `Debug:ChangeLevel` (4 of 4): `CChangeLevelIssue::ExecuteCommand` (0x5432c0, slot 11 of its table) and `CVEngineServer::ChangeLevel` (engine.dll 0x13ad90, slot 0 of a 125-slot table that matches Linux's) are located and left out of the table: the mod builds all four addresses itself as static `CAddr_Sym`s (`changelevel.cpp:15`), and a table block under the same name would be a duplicate of them. `CanCallVote` is no symbol of server_srv.so on 11117211 (the virtual is `RequestCallVote`) and `Host_Changelevel_f` none of engine_srv.so, so both fail on Linux as well
- `Debug:Flamethrower_Mojo` (3 of 16): `CTFFlameEntity::Create` (open: the only reference to the `tf_flame` class string is the factory registration at 0x50cb6, so it has no body of a shape I could find), `CTFFlameEntity::RemoveFlame` (bad), `CBaseProjectile::CollideWithTeammatesThink` (refused: 0x20f020 is `mov byte [ecx+0x4b4], 1; ret`, the think `SetLauncher` and `Spawn` store, and a detour on a body that short is turned away)
- `Debug:Known_Entities` (2 of 17): `CTFBot::StopSuspectingSpy` and `CTFBot::SuspectedSpyInfo_t::IsCurrentlySuspected` (both bad)
- `Debug:MedigunShield_Obstruction` (1 of 3): `ILocomotion::TraceHull` (clone: the `.isra.0` copy takes its vectors in eax, edx and ecx)
- `Debug:Robot_Pose_Parameters` (1 of 2): `CTFPlayer::ShouldDropAmmoPack` (bad)
- `Debug:Scale_Rate` (6 of 6): `CTFPlayer::GetDesiredHandScale`, `GetDesiredHeadScale`, `GetDesiredTorsoScale`, `GetHandScaleSpeed`, `GetHeadScaleSpeed`, `GetTorsoScaleSpeed` (all bad: inline in `TFPlayerThink`)
- `Debug:ShortCircuit_RubberBand` (1 of 3): `CTFMechanicalArm::ShockAttack` (bad)
- `Debug:Suicide_Bomber` (1 of 6): `Path::Compute_vec<CTFBotPathCost>` (no entry in any gamedata file, so it fails on Linux too)
- `Debug:Tele_Sapper` (1 of 4): `CBaseObject::HasSapper` (refused: 0x4c18c0 is `mov al, [ecx+0xa4c]; ret`)
- `Debug:VProf_Record` (2 of 2): `VProfRecord_Snapshot`, `VProfRecord_StartOrStop` (no such symbols in engine_srv.so on 11117211; the Linux entries are byte patterns, not symbols)
- `Debug:Vaccinator` (1 of 1): `CheckMedicResist` (clone: `.part.0` with `__gcc_regcall`, and the mod body is a TODO that calls through)
- `Visualize:Flamethrower` (2 of 4): `CTFFlameEntity::Create`, `CTFFlameEntity::RemoveFlame` (as for Flamethrower_Mojo)

## Left out of the Windows package

- `Etc:Workshop_Map_Fix`: watches the workshop directory with inotify and links maps with symlinks, and its Steam UGC callbacks are folded into one function on Windows. `shipped.py` leaves its source out.
- `Perf:SendProp_Optimize`: replaces `CBaseEntity::SetTransmit` and `CBaseEdict::GetChangeAccessor` whole with `MOD_ADD_REPLACE_FUNC_MEMBER`, and `CFuncReplace` has no function size to check under MSVC (`mem/patch.h`), so the mod would fail to load. Nine of its 26 detours have no Windows address either: the two `CParallelProcessor<>::Run` engine template instances, `CAnimationLayer::StudioFrameAdvance`, `CBaseAnimatingOverlay::SetLayerCycle`, `CTFPlayer::RemoveObject`, `CBaseCombatWeapon::OnActiveStateChanged` (the 16-byte `ret 4` stub at 0x130600, shared by every class that does not override it) and three GCC `.part` clones. It is off by default on Linux too. `shipped.py` leaves its source out.
- `Perf::Virtual_Call_Optimize_Inline_Virtuals`: rewrites GCC call sites of virtuals into direct loads; MSVC's call sites have another shape. `#if !defined _WINDOWS` in `virtual_call_optimize.cpp`, with its convar. The rest of `Perf::Virtual_Call_Optimize` is ported; its `CBaseEntity::GetTeamNumber` patch rewrites the GCC body and is left out too.
- `Perf::CSS_Bot_Vision_Optimize`: Counter-Strike: Source bot classes, under `SE_IS_CSS`; the TF2 server has no `CCSBot`.
- Within shipped mods: `CTFPlayer::CanBeForcedToLaugh`'s `CAddr` in `addr/misc.cpp` (the table has the function), and `Util:Overlay_Send`'s detours on the two `NDebugOverlay::Cross3DOriented` overloads, which have no body in server.dll since nothing calls them.

## Inlined functions and what the Windows build loses

Each was checked to have no standalone body on 11117211: the only Linux caller holds the inline, and the strings or the callee that would belong to a standalone copy appear once.

| Function | Inline in | Feature lost on Windows |
| --- | --- | --- |
| `CTFFlameManager::BCanBurnEntityThisFrame` | `OnCollide` 0x46eba0 (0x46ed22) | `max_aoe_targets` restored by a throttle in an `OnCollide` detour; the counter moves when a collision passes rather than when the game would burn |
| `CTFPlayer::IsAllowedToInitiateTauntWithPartner` | `PlayTauntSceneFromItem` 0x506230 | `Custom_Attributes` always_allow_taunt; no stand-in: the checks sit mid-function and the attribute is per player, so a byte patch would allow partner taunts for everyone |
| `CTFPlayer::MaybeDrawRailgunBeam` | `FireBullet` 0x51fe50 | `Weapon_Shoot` custom tracer particle and broadcast beam; a scoped `TE_TFParticleEffectComplex` detour could swap the filter, not done untested |
| `CTFPlayer::SpyDeadRingerDeath` | `OnTakeDamage` 0x500c70 | none: `Custom_Attributes` and `Human_Death_Yells` hook `FeignDeath` (0x4f0750) called with deathnotice true |
| `CTFWeaponBase::Energy_Recharge` | `IncrementAmmo` 0x636170 | none: `reload_full_clip_at_once` hooks `IncrementAmmo` |
| `CTFPlayer::ShouldDropAmmoPack` | `Event_Killed` 0x4ec3b0 | none: `Drop_Weapons` and `TFBot_Extensions` drop in an `Event_Killed` detour |
| `CTFBotMainAction::SelectCloserThreat` | `SelectMoreDangerousThreatInternal` | none: native body in `stub/tfbot_behavior.cpp` |
| `CTFBot::StopSuspectingSpy` | `ForgetSpy` 0x551770 | `Debug:Known_Entities` has no detour on it; its `ForgetSpy` detour spans it |
| `CTFBot::SuspectedSpyInfo_t::IsCurrentlySuspected` | `CTFBotVision::IsVisibleEntityNoticed` 0x566ff0 | `Debug:Known_Entities` has no detour on this test |
| `CTFBotProxy::CTFBotProxy` | `CEntityFactory<CTFBotProxy>::Create` 0x594180 | `Debug:CTFBotProxy` has no detour on the constructor |
| `CTFMechanicalArm::ShockAttack` | `SecondaryAttack` 0x61a020 (from 0x116) | `Debug:ShortCircuit_RubberBand` has no detour on the shock |
| `CTFFlameEntity::RemoveFlame` | `FlameThink` 0x609b60 and `OnCollide` 0x60ac10 | `Debug:Flamethrower_Mojo` and `Visualize:Flamethrower` have no detour on a flame's removal |
| `CTFPlayer::GetDesiredHandScale`, `GetDesiredHeadScale`, `GetDesiredTorsoScale`, `GetHandScaleSpeed`, `GetHeadScaleSpeed`, `GetTorsoScaleSpeed` | `TFPlayerThink` 0x50faa0 | `Debug:Scale_Rate` has no detour on any of the six, so it changes nothing on Windows |
| `CTFWeaponBaseGun::UpdatePunchAngles` | `FireProjectile` 0x63b430 | none: `Util:Vehicle_Fix` saves the punch angle around a `FireProjectile` detour for a player in a vehicle |
| `CBaseCombatCharacter::CalculatePhysicsStressDamage` | `ApplyStressDamage` 0x1d4010 | none: `Util:Vehicle_Fix` detours `ApplyStressDamage` and returns early for players |

`CTFBot::IsExplosiveProjectileWeapon` is not inlined: it is 0x556fa0, a jump-table switch on the weapon id (ids 0x16, 0x17, 0x18, 0x3c, 0x41), called once from `FireWeaponAtEnemy`. My first batch recorded it as inlined from the wrong evidence.

`CTFPlayer::UpdateExpression` is not inlined everywhere: 0x4f1dd0 is a standalone copy (stored as a function pointer at 0x4f6b75); `TFPlayerThink` (0x50faa0) also carries one inline, which the `Entity_Limit_Manager` detour does not reach.

`EconItemInterface_OnOwnerKillEaterEvent` was pinned to 0x48a4a0, which is the Batched wrapper; the non-batched interface body is 0x48a9f0 and 0x48a4a0 is now the Batched entry.

## Client-side only gaps

These hook the game client and have no meaning in a dedicated server: `Anim:EstimateAbsVelocity_MoveParent_Fix`, `Debug:Client_Desync`, `Debug:Sound_Leak`, `Etc:LaserDot_Fix`, `Etc:Override_Move_Speed`, `Prof:Debug_Overlay`, `Prof:Tier2_RenderUtils`, `Util:DebugOverlay_Font`, `Util:DebugOverlay_Font_v2`, `Util:DebugOverlay_Font_v3`, `Util:Notify_Recv`, `Util:Overlay_Enhancements`, `Util:Overlay_Recv`.

Checked against `gamedata/sigsegv/client.txt`, where every missing name of the 13 (11 in the package, `Debug:Client_Desync` and `Debug:Sound_Leak` outside it) is a `[client]` entry: `C_BaseEntity`, `C_TFPlayer`, `C_SniperDot` and `CTFGameMovement` in `client.dll`; `CMatSystemSurface::DrawColoredText`, `CFontTextureCache` and the texture filters in `vguimatsurface.dll`; `CDebugOverlay::DrawAllOverlays` and `DrawOverlay`, the `Render*` helpers and `S_Play` in the engine's render and sound code. A dedicated server loads no `client.dll` or `vguimatsurface.dll` and never enters the engine's renderer or sound system, so nothing runs those functions and the missing addresses cost nothing. `Etc:Override_Move_Speed` also has a server-side `CTFGameMovement` detour, which resolves.

## Compiled out on both platforms

- `AI:MvM_Defender_Bots`: source commented out in AMBuilder (`src/mod/ai/mvm_defender_bots.cpp`)
- `Bot:Demo_Elevation_Fix`: body under #if 0 in the source (`src/mod/bot/demo_elevation_fix.cpp`)
- `Common:Common`: not listed in AMBuilder (`src/mod/common/common.cpp`)
- `Credits:Magnet_Disable`: source commented out in AMBuilder (`src/mod/credits/magnet_disable.cpp`)
- `Debug:Crit_Chance`: not listed in AMBuilder (`src/mod/debug/crit_chance.cpp`)
- `Debug:Func_Nav_Cost_Tags`: source commented out in AMBuilder (`src/mod/debug/func_nav_cost_tags.cpp`)
- `Debug:Override_Step_Sound`: not listed in AMBuilder (`src/mod/debug/override_step_sound_v1.cpp`)
- `Debug:PopMgr_Exploit`: source commented out in AMBuilder (`src/mod/debug/popmgr_exploit.cpp`)
- `Debug:PopMgr_MultiParse`: source commented out in AMBuilder (`src/mod/debug/popmgr_multiparse.cpp`)
- `Debug:Scheme_Load`: source commented out in AMBuilder (`src/mod/debug/scheme_load.cpp`)
- `Debug:Upgrade_Tiers`: body under #if 0 in the source (`src/mod/debug/upgrade_tiers.cpp`)
- `Etc:Debug_Mission_Change_Crash`: source commented out in AMBuilder (`src/mod/etc/debug_mission_change_crash.cpp`)
- `Perf:Clientside_Wearable_Optimize`: not listed in AMBuilder (`src/mod/perf/clientside_wearable_optimize.cpp`)
- `Prof:Attr_Munge`: source commented out in AMBuilder (`src/mod/prof/attr_munge.cpp`)
- `Util:JumboFrames`: source commented out in AMBuilder (`src/mod/util/jumboframes.cpp`)
- `Util:NetMsg_Client`: source commented out in AMBuilder (`src/mod/util/netmsg_client.cpp`)
- `Util:NetMsg_Server`: source commented out in AMBuilder (`src/mod/util/netmsg_server.cpp`)
- `Util:Screenshot_PNG`: source commented out in AMBuilder (`src/mod/util/screenshot_png.cpp`)
- `Util:Serialize_Spew`: source commented out in AMBuilder (`src/mod/util/serialize_spew.cpp`)
- `Util:VProf_Remote`: source commented out in AMBuilder (`src/mod/util/vprof_remote.cpp`)
- `Util:VProf_Remote_Test`: source commented out in AMBuilder (`src/mod/util/vprof_remote.cpp`)
- `Visualize:Airblast_Cone`: body under #if 0 in the source (`src/mod/visualize/airblast_cone.cpp`)
- `Visualize:Airblast_Vectors`: body under #if 0 in the source (`src/mod/visualize/airblast_vectors.cpp`)

## Enabled and fully resolved

In the Windows package (182):

- AI (15): `EngieBot_Dispensers`, `EngieBot_NoPush`, `EngieBot_Wrangler`, `Focus_One_Player`, `Giant_Pyro`, `Improved_Targeting`, `Improved_UseItem`, `My_Nextbot`, `My_Nextbot_Unlag`, `My_Nextbot_UnlagNPCGlobal`, `NextBotEventResponder_Hooks`, `Prevent_Postmortem_Updates`, `Puppet`, `RocketJump`, `WrapAssassin_AltFire`
- Anim (1): `Player_UpdateModel_AnimState_Fix`
- Attr (5): `BlockBackstab_OldStyle`, `CustomProjectileModel_Precache`, `Custom_Attributes`, `HealOnKill_Overheal_Melee`, `Undocumented`
- Bot (9): `Bot_Player_Slot_Reorder`, `IsSpaceToSpawnHere_Scale`, `Kart_Locomotion`, `Kill_Before_ForceSpec`, `Medieval_NonMelee`, `MultiClass_Weapon`, `RunFast`, `Spy_MedicHeal`, `Spy_SelectRandomReachableEnemy`
- Canteen (1): `Share_Recall_Canteen`
- Common (5): `Commands`, `ExtraEntityData`, `Interrupt_Action`, `Text_Hud`, `Weapon_Shoot`
- Cond (2): `Enhanced_Cmds`, `Reprogrammed`
- Credits (2): `Better_Radius_Collection`, `Spawn_AutoCollect`
- Debug (1): `UserMsg_Overflow`
- Demo (1): `StringTable_Limit`
- Etc (34): `Allow_Civilian_Class`, `Crash_Fixes`, `CrayAirblast_ConVar_NoCheat`, `Deflect_Rocket_Spew`, `Detector`, `Entity_Limit_Manager`, `Entity_Limit_Manager_Convert_Serverside`, `Heat_Seeking_Rockets`, `Holiday_Items_Allow`, `Huntsman_Damage_Fix`, `Instant_Scaling`, `Limp_Projectiles`, `Loose_Cannon_Damage_Fix`, `MM_Spoof`, `Mapentity_Additions`, `Medicgun_Beam_Machinery`, `Melee_Ignore_Teammates`, `Misc`, `Misc:AllowVoteMidWave`, `Misc:HHHHealthBar`, `Misc:ScriptSaveLimit`, `Misc:SentryBusterParticleChange`, `Misc:SpectatorVoteFix`, `Nav_UpdateBlocked`, `Nav_UpdateBlocked_Visualize`, `Player_Bullet_Bounding_Fix`, `RateLimit_Exclude`, `SendProp_Override`, `SendProp_Override_Extension`, `Suppress_NB_Event_Messages`, `Target_ChangeGravity_Improved`, `Trigger_Filter_Fix`, `Unintended_Class_Weapon_Improvements`, `Weapon_Mimic_Teamnum`
- Item (1): `Item_Common`
- MvM (34): `Blu_Velocity_Limit_Remove`, `ChangeBotAttributes_Crash_Fix`, `ChangeClass_AnyTime`, `Chat_Unrestrict`, `Disposable_Dispenser`, `Disposable_Sentry_Health_Upgrades`, `Dominations`, `Drop_Weapons`, `Explosive_Headshot_On_Everything`, `Extended_Upgrades`, `FriendlyFire`, `Gamemode_Converter`, `Gib_Improvements`, `Human_Death_Yells`, `JoinTeam_Blue_Allow`, `MedigunShield_Damage`, `No_Halloween_Souls`, `Player_Limit`, `Red_Robot_Eye_Glow`, `Refund_Exploit_Fix`, `RoboSapper_Override`, `Robot_Limit`, `Robot_Multiplier`, `Sapper_Allow_Multiple_Active`, `SentryBuster_Enhancements`, `Set_Credit_Team`, `Sub_Wave_Spawn_At_Once`, `Teleporter_Aggro`, `UpgradeStation_Regen_Improved`, `Upgrade_Disallow`, `Wave_Spawn_At_Once`, `Weapon_AntiGrief`, `Weapon_Balancing`, `YER_Unnerf`
- Perf (18): `:Func_Optimize`, `:Idle_Optimize`, `:Input_Optimize`, `:Virtual_Call_Optimize`, `Attributes_Optimize`, `Extra_Player_Slots`, `Extra_Player_Slots_Bots`, `Extra_Player_Slots_Players`, `Filesystem_Optimize`, `Flame_Breakable_Collision`, `HLTV_Client_Interact`, `HLTV_Optimize`, `Medigun_Shield_Damage_Events`, `Medigun_Shield_Damage_Interval`, `Medigun_Shield_Pathfinding`, `MvM_Load_Popfile`, `SmokeStack_FS_Thrash`, `Squad_Escort_Optimize`
- Pop (15): `ECAttr_Extensions`, `EventPopfile_Improvements`, `ExtAttr:AlwaysFireWeaponAlt`, `ExtAttr:IgnoreTargets`, `ExtAttr:Parse`, `ExtAttr:TargetStickies`, `KV_Conditional`, `Mission_Extensions`, `Nested_Complex_Spawners`, `PointTemplates`, `PopMgr_Extensions`, `TFBot_Extensions`, `Tank_Extensions`, `WaveSpawn_Extensions`, `Wave_Extensions`
- Prof (4): `Flame_Breakable_Collision`, `Frame_Prof`, `MvM_Shield_Events`, `Popfile_Load`
- Robot (7): `Building_Stomp`, `No_Canteens`, `Spawn_Protection_Fix`, `Spawn_SetName`, `Standable_Heads`, `Ticklish`, `Underground_Check_Override`
- Sniper (2): `Charge_Uncap`, `Head_Uncap`
- Sound (5): `Suppress_Giant_SentryBuster`, `Suppress_MedicBot_Shield`, `Tele_Activate`, `Unused_Credits`, `Unused_Sapper`
- Tank (1): `Gunslinger_Combo`
- Util (19): `Client_Cmds`, `ConFilter`, `Console_Recv`, `Console_Send`, `DTWarning_Use_CVar`, `Download_Manager`, `Entity_Overlays`, `ListenServerHost`, `Lua`, `Make_Item`, `Notify_Send`, `Overlay_Send`, `Pooled_String`, `Pooled_String_Fix`, `VProf_Recv`, `VProf_Send`, `VScript_Load_Init_Scripts`, `VScript_Send_Output_To_Admins`, `Vehicle_Fix`

Debug, Visualize and VGUI tools, outside the package (74):

- Debug (54): `AirblastVuln`, `Backtrace`, `Better_Ent_Text`, `Bottle_Break`, `Building_Status`, `Client_Player_Track`, `Cond_Stunned`, `Conds`, `Console_Scramble_v1`, `Console_Scramble_v2`, `Console_Scramble_v2_PartA`, `Console_Scramble_v2_PartB`, `Credit_Magnet`, `Damage_Overlay`, `Deflect_Angle`, `Deflect_Angle_v2`, `Draw_CPhysCollide`, `EnergyRing_Knockback`, `FeignDeath_Ragdoll`, `Flamethrower_Impulse_101`, `Flamethrower_Misc`, `GetPlayerMaxSpeed`, `Grenade_Logger`, `Grenade_VPhysics`, `Heal_Debuff`, `IsPotentiallyTraversable_Trace`, `Max_Clients`, `Medigun_Speed`, `Melee_Trace`, `Minigun_State`, `MvM_Shield_FPS`, `Nav_Mesh`, `NextBot`, `NextBot_Input`, `NoKnockback`, `OnKilled_Before_MainAction_Start`, `Owners`, `Parachute_Warp`, `Penetration`, `Proj_Energy_Ball`, `Projectile_Motion`, `Quantum_Duck`, `Rage`, `Revive_Exploit`, `Revive_Fast`, `SentryBuster_Mannhattan`, `Sticky_Detonation_Delay`, `Sticky_Detonation_Order`, `TF_Nav_Mesh_Trace`, `Tank_Destroy_Animation`, `Tele_AutoDetonate`, `TeleportWhere`, `UseItem_Broken`, `UserMsg_Overflow_v2`
- VGUI (1): `Test`
- Visualize (19): `Airblast_Box`, `Ammo_Counts`, `Backstab`, `Blast_Radius`, `Conds`, `Conds_Client`, `Damage_Force`, `Dispenser_Radius`, `Engie_Nests`, `Explosive_Headshot`, `Hitboxes`, `Huntsman`, `Jar_Radius`, `Melee_Range`, `Minigun_Deflect`, `Projectile_Speed`, `Projectile_Trail`, `Sapper_Range`, `Taunt_Attacks`

## Address names used by the code with no Windows entry

Names defined in `gamedata/sigsegv` and named in the sources the Windows package compiles, outside a comment and outside code Windows does not compile, with no entry in `windows.txt`, not resolved at run time, not `bad` and not `[client]`: 66, from `tools/winport/namegaps.py --list --shipped`. Some are never reached on a dedicated server; the bed logs the ones a mission reaches (`unresolved functions called`). The free-function group also holds gamedata keywords (`addrs`, `sym`, `{`) that `namegaps.py` picks up from strings in `src/`. Grouped by class.

- `Action<CTFBot>` (5): `ApplyResult`, `BuildDecoratedName [clone]`, `InvokeOnEnd`, `InvokeOnResume`, `PrintStateToConsole`
- `Action<CZombie>` (5): `ApplyResult`, `BuildDecoratedName [clone]`, `InvokeOnEnd`, `InvokeOnResume`, `PrintStateToConsole`
- `Behavior<CTFBot>` (1): `FirstContainedResponder`
- `CAttributeList` (4): `GetAttributeByID`, `GetAttributeByName`, `NotifyManagerOfAttributeValueChanges`, `SetRuntimeAttributeRefundableCurrency`
- `CBaseEntity` (1): `GetTeamNumber`
- `CModelLoader` (1): `FlushDynamicModels`
- `CPlayer` (1): `GetEdict`
- `CStaticProp` (2): `GetEntityHandle`, `GetRefEHandle`
- `CStaticPropMgr` (3): `GetStaticPropIndex`, `LevelInit`, `LevelShutdown`
- `CTFBotUseItem` (1): `CTFBotUseItem [C1]`
- `CThreadLocalBase` (1): `Get`
- `INextBot` (2): `IsRangeGreaterThan`, `IsRangeLessThan`
- `NextBotPlayer<CTFPlayer>` (1): `GetEntity`
- `Path` (3): `BuildTrivialPath`, `ComputePathDetails`, `Optimize`
- `(free functions)` (35): `COM_CompressBuffer_LZSS`, `ENTINDEX`, `FireEvent`, `GEconItemSchema`, `GetParticleSystemNameFromIndex`, `MapEntity_ParseToken`, `PrecachePointTemplates`, `SendCvarValueQueryToClient`, `SendProxy_LengthTable`, `SendProxy_StringToString`, `TE_BeamPoints`, `TE_BeamRingPoint`, `TE_BreakModel`, `TE_PhysicsProp`, `TheNextBots`, `addrs`, `addrs_group`, `attribute_class`, `attribute_type`, `description_format`, `description_string`, `effect_type`, `g_arFakePorts`, `g_bUseFakeIP`, `g_nFakeIP`, `lib`, `modelloader`, `name`, `regex`, `s_StaticPropMgr`, `server`, `sigsegv`, `sym`, `{`, `}`

Recorded `bad` (4): `CAttributeList::AddAttribute`, `NDebugOverlay::Cross3DOriented_ang`, `NDebugOverlay::Cross3DOriented_mat`, `NextBotManager::CollectAllBots`.

## The four entries carry.py could not carry to 11117211

`overrides.json` held them at 11087207, so `emitgamedata.py` left them out of the 11117211 table.

| Entry | Result on 11117211 |
| --- | --- |
| `ConColorMsg` (tier0.dll) | unmoved at 0x45a0, still the `?ConColorMsg@@YAXABVColor@@PBDZZ` export |
| `_SpewMessage` (tier0.dll) | unmoved at 0x4bf0, still the callee of the exported `_SpewMessage` (0x6640) |
| `SQVM::Call` (vscript.dll) | unmoved at 0x2dfa0, only xref of the `SCRIPT PERF WARNING` string (0x2e138), `ret 0x14` |
| `CTFProjectile_BallOfFire::Burn` | 0x534bd0 (0 matches because the body changed): called from `RocketTouch` (0x5349c0), strings `Weapon_DragonsFury.BonusDamage`, `BonusDamageHit`, `BonusDamagePain`, `ret 4` |

The three library entries were byte-identical, so `carry.py`'s `unmoved` check should have kept them; the old binaries for 11087207 are no longer served, so they were re-read by hand. All four are in the table now (1,627 to 1,631 entries).

## Notes on stand-ins

- `max_aoe_targets`: the Windows throttle sits in Custom_Attributes' `OnCollide` detour, in front of the inline `BCanBurnEntityThisFrame`. Its counter moves whenever a collision passes the throttle; Linux moves it only when the game would burn. A collision the game rejects for its own per-entity interval therefore also uses up the slot, and the flamethrower can burn slightly less often than on Linux.
- `MaybeDrawRailgunBeam` is inline in `FireBullet` (0x51fe50), whose only call to `TE_TFParticleEffectComplex` (0x52082f) is the beam. Weapon_Shoot detours that call while `FireBullet` runs and, for the `dxhr_sniper_rail*` particles, dispatches the custom tracer and swaps in a broadcast filter as its Linux `MaybeDrawRailgunBeam` detour does. It has not been run on the bed.
- `Util:Overlay_Send`: its 30 `[local]` entries are `CAddr_Pointer`s to the mod's own functions and need no table entry. Its detours on the two `NDebugOverlay::Cross3DOriented` overloads are not registered on Windows: server.dll has no body for either, since nothing calls them.
- `Perf:HLTV_Optimize`: `CHLTVDemoRecorder::StopRecording [clone]` is a GCC `.part` clone; the Windows function has no clone and the plain `StopRecording` detour covers it.
- `Perf:SendProp_Optimize` is left out of the package (above). If it is ever ported: server.dll's `CBaseEdict::GetChangeAccessor` is 0x271800 (`engine->GetChangeAccessor(this)` through slot 0x5d of the engine interface, called by `NetworkStateChanged` 0x14f3c0 and about a hundred other sites), not the engine.dll body the table names today, and `CFuncReplace` needs a Windows form, such as a `jmp rel32` to the replacement over the first five bytes.
- `Util:Vehicle_Fix`: `CBasePlayer::GetInVehicle` has no `.part` clone on Windows and the detour sits on the function. `UpdatePunchAngles` is inline in `FireProjectile`, so a `FireProjectile` detour saves `m_vecPunchAngle` for a player in a vehicle and restores it after. `CalculatePhysicsStressDamage` is inline in `ApplyStressDamage(IPhysicsObject *, bool)` (0x1d4010), whose detour returns early for a player. `DriveVehicle` is slot 233 of `CPropVehicleDriveable`'s primary table (0x371d20) and `PassengerShouldReceiveDamage` slot 12 of `CBaseServerVehicle`'s (0x377400). Not run on the bed, to check there.
- `MvM:MedigunShield_Damage`: `CTFMedigunShield::Create` is inline in `CWeaponMedigun::CreateMedigunShield` on Windows, so the mod colours the shield in a virtual hook on `CBaseEntity::SetOwnerEntity` (slot 18 of `CTFMedigunShield`'s table), which that code calls once on the new shield.
- `Perf:Func_Optimize`: `CTFPlayer::PrecacheMvM` is inline in `CTFGameRules::Precache` (0x499ca0), so on Windows the Rome promo items are precached in a `Precache` detour when the map name, without a `workshop/` prefix, starts with `mvm_`.
- `Perf::Virtual_Call_Optimize`: the `CStaticPropMgr::IsStaticProp` (two overloads) and `GetStaticProp` replacements have MSVC `thiscall` byte forms and read `CStaticProp`'s table by its RTTI name `.?AVCStaticProp@@`; engine.dll 0x1d4290, 0x1d42c0 and 0x1d3bf0.
