# Windows coverage of SigMod mods and addresses

Measured on 2026-10-14 against TF2 ServerVersion 11117211 (depot 232255), main `39249833` plus `mfe/feat/winport-coverage`. Static: it reads the code and `gamedata/sigsegv/windows.txt`, not a bed run. `tools/winport/modgaps.py` is the base of the mod count (detours and virtual hooks only); the bed's `sig_list_mods` remains the truth for what actually loads, and the 20 FAILED mods in `status/20261009-sweep-after-mod-batch/` are failures of patches and virtual hooks that this file cannot see.

## How it works

- Linux resolves each name by symbol from `server_srv.so`. Windows `server.dll` is stripped, so `windows.txt` is loaded first and holds a `fixed` RVA per name (`CSigsegvGameConf::NameTaken` drops later blocks under the same name). It is derived: `matchfuncs.py`/`matchvtables.py` pair Linux and Windows functions, `tools/winport/overrides.json` (hand entries keyed by Linux symbol, each with `build`, `why`, or `bad`) wins over the matches, `emitgamedata.py` writes the table, `carry.py`/`rebase.py` move overrides to a new build, `checktable.py` and `dupes.py` guard it. Entries for another build are ignored, and `SDK_OnLoad` refuses to load on a build the table is not for.
- Some names need no table entry: `func knownvtidx` and `.?AV` vtable slots, `func ebpprologue`, `datamap`, `convar` and `src/addr/*.cpp` classes resolve at run time on Windows (`FindAddrWin`). This file counts them as resolved; whether each does on a given build only a bed run says.
- No mod is compiled out for Windows by an `#ifdef`. `_WINDOWS` guards inside mods swap individual detours for Windows equivalents. A mod is out only when its source is commented out of `AMBuilder` or its body is under `#if 0`, which is true on Linux too. Mods the bed lists as DISABLED (71 of 195) are loaded but off until a convar or popfile key turns them on.
- `IMod::InvokeLoad` on Windows loads a mod without its failed detours; a failed patch or virtual hook fails the whole mod, and `Toggle` then keeps it off.

## Totals

| Status | Mods |
| --- | ---: |
| Enabled, every detour and virtual hook has an address | 237 |
| Enabled, server-side detours or hooks without an address | 36 |
| Enabled, only client-side addresses missing (nothing to hook on a dedicated server) | 13 |
| Compiled out on both platforms | 23 |
| All SigMod mods (`IMod`/`CModule` names) | 309 |

Of the 36 with gaps (30 after the second batch), the mission-facing mods are at zero unresolved detours: every remaining gap is under `#if !defined _WINDOWS` with the feature it loses listed below. What is left is `Debug:`, `Visualize:` and `Prof:` tools, `Etc:Workshop_Map_Fix`, `Util:Vehicle_Fix`, `Util:Overlay_Send` and four `Perf:` mods.

Address names: 2,860 are defined in the Linux gamedata, 2,163 of them are named in `src/`. Of those 2,163: 1,450 have a `windows.txt` entry, 214 resolve at run time, 14 are recorded `bad` (inlined, no body of their own), 43 are client-side, and **442 have no Windows entry**.

## Enabled mods with unresolved addresses

`missing`: no entry and no override. `bad`: read by hand, no body of its own on 11117211.

- `Debug:CTFBotProxy` (2 of 4): `CTFBotProxy::CTFBotProxy [C1]` (missing), `CEventQueue::AddEvent [EventQueuePrioritizedEvent_t *]` (missing)
- `Debug:ChangeLevel` (4 of 4): `CChangeLevelIssue::CanCallVote` (missing), `CChangeLevelIssue::ExecuteCommand` (missing), `CVEngineServer::ChangeLevel` (missing), `Host_Changelevel_f` (missing)
- `Debug:Flamethrower_Mojo` (6 of 16): `CTFFlameThrower::GetFlameOriginPos` (missing), `CTFFlameEntity::Create` (missing), `CTFFlameEntity::RemoveFlame` (missing), `CBaseProjectile::CollideWithTeammatesThink` (missing), `CBaseEntity::PhysicsNoclip` (missing), `CBaseEntity::PhysicsRunThink` (missing)
- `Debug:Known_Entities` (10 of 17): `CTFBot::IsSuspectedSpy` (missing), `CTFBot::StopSuspectingSpy` (missing), `CTFBot::IsKnownSpy` (missing), `CTFBot::RealizeSpy` (missing), `CTFBot::ForgetSpy` (missing), `CTFBot::SuspectedSpyInfo_t::Suspect` (missing), `CTFBot::SuspectedSpyInfo_t::IsCurrentlySuspected` (missing), `CTFBot::SuspectedSpyInfo_t::TestForRealizing` (missing), `CTFBot::DelayedThreatNotice` (missing), `CTFBotMainAction::OnInjured` (missing)
- `Debug:MedigunShield_Obstruction` (1 of 3): `ILocomotion::TraceHull` (missing)
- `Debug:OnKilled_Before_MainAction_Start` (3 of 5): `CTFBotMainAction::OnStart` (missing), `CTFBotFetchFlag::OnStart` (missing), `INextBot::DisplayDebugText` (missing)
- `Debug:Revive_Fast` (2 of 3): `CTFReviveMarker::AddMarkerHealth` (missing), `CTFReviveMarker::ReviveThink` (missing)
- `Debug:Robot_Pose_Parameters` (2 of 2): `CTFWearable::CanEquip` (missing), `CTFPlayer::ShouldDropAmmoPack` (bad)
- `Debug:Scale_Rate` (6 of 6): `CTFPlayer::GetDesiredHandScale` (missing), `CTFPlayer::GetDesiredHeadScale` (missing), `CTFPlayer::GetDesiredTorsoScale` (missing), `CTFPlayer::GetHandScaleSpeed` (missing), `CTFPlayer::GetHeadScaleSpeed` (missing), `CTFPlayer::GetTorsoScaleSpeed` (missing)
- `Debug:ShortCircuit_RubberBand` (1 of 3): `CTFMechanicalArm::ShockAttack` (missing)
- `Debug:Sticky_Detonation_Delay` (4 of 8): `CTFGrenadeLauncher::SecondaryAttack` (missing), `CTFPipebombLauncher::SecondaryAttack` (missing), `CTFPlayer::CanAttack` (missing), `CTFWeaponBase::CanPerformSecondaryAttack` (missing)
- `Debug:Suicide_Bomber` (1 of 6): `Path::Compute_vec<CTFBotPathCost>` (missing)
- `Debug:Tele_Sapper` (2 of 4): `CBaseObject::HasSapper` (missing), `CBaseObject::SetPlasmaDisabled` (missing)
- `Debug:UseItem_Broken` (1 of 6): `CTFBot::PushRequiredWeapon` (missing)
- `Debug:UserMsg_Overflow` (2 of 7): `SVC_UserMessage::WriteToBuffer` (missing), `SVC_UserMessage::ReadFromBuffer` (missing)
- `Debug:UserMsg_Overflow_v2` (1 of 2): `CNetChan::SendNetMsg` (missing)
- `Debug:VProf_Record` (2 of 2): `VProfRecord_Snapshot` (missing), `VProfRecord_StartOrStop` (missing)
- `Debug:Vaccinator` (1 of 1): `CheckMedicResist` (missing)
- `Etc:Workshop_Map_Fix` (5 of 8): `CTFWorkshopMap::OnUGCItemInstalled` (missing), `CTFMapsWorkshop::Steam_OnUGCItemInstalled` (missing), `CTFMapsWorkshop::AddMap` (missing), `CDownloadListGenerator::OnResourcePrecachedFullPath` (missing), `CVEngineServer::FindMap` (missing)
- `Perf::CSS_Bot_Vision_Optimize` (3 of 3): `CCSBot::IsVisible` (missing), `CCSBot::GetPartPosition` (missing), `CCSBot::FindMostDangerousThreat` (missing)
- `Perf::Virtual_Call_Optimize_Inline_Virtuals` (1 of 5): `CServerNetworkProperty::GetClassName` (missing)
- `Perf:HLTV_Optimize` (1 of 12): `CHLTVDemoRecorder::StopRecording [clone]` (missing)
- `Perf:SendProp_Optimize` (16 of 27): `CHLTVClient::SendSnapshot` (missing), `CParallelProcessor<PackWork_t>::Run` (missing), `CAnimationLayer::StudioFrameAdvance` (missing), `CBaseAnimatingOverlay::FastRemoveLayer [clone]` (missing), `CBaseAnimatingOverlay::FastRemoveLayer` (missing), `CBaseAnimatingOverlay::SetLayerCycle` (missing), `CMultiPlayerAnimState::RestartGesture [clone]` (missing), `CTFPlayer::AddObject [clone]` (missing), `CTFPlayer::RemoveObject` (missing), `AllocChangeFrameList` (missing), `SendTable_CullPropsFromProxies` (missing), `CVEngineServer::CheckAreasConnected` (missing), `CGameClient::SetupPackInfo` (missing), `CParallelProcessor<CGameClient *>::Run` (missing), `InvalidateSharedEdictChangeInfo` (missing), `CBaseCombatWeapon::OnActiveStateChanged` (missing)
- `Util:Overlay_Send` (32 of 90): `[local] NDebugOverlay::Box` (missing), `[local] NDebugOverlay::BoxDirection` (missing), `[local] NDebugOverlay::BoxAngles` (missing), `[local] NDebugOverlay::SweptBox` (missing), `[local] NDebugOverlay::EntityBounds` (missing), `[local] NDebugOverlay::Line` (missing), `[local] NDebugOverlay::Triangle` (missing), `[local] NDebugOverlay::EntityText` (missing), `[local] NDebugOverlay::EntityTextAtPosition` (missing), `[local] NDebugOverlay::Grid` (missing), `[local] NDebugOverlay::Text` (missing), `[local] NDebugOverlay::ScreenText` (missing), `[local] NDebugOverlay::Cross3D_ext` (missing), `[local] NDebugOverlay::Cross3D_size` (missing), `[local] NDebugOverlay::Cross3DOriented_ang` (missing), `[local] NDebugOverlay::Cross3DOriented_mat` (missing), `[local] NDebugOverlay::HorzArrow` (missing), `[local] NDebugOverlay::YawArrow` (missing), `[local] NDebugOverlay::VertArrow` (missing), `[local] NDebugOverlay::Axis` (missing), `[local] NDebugOverlay::Sphere` (missing), `[local] NDebugOverlay::Circle` (missing), `[local] NDebugOverlay::Circle_ang` (missing), `[local] NDebugOverlay::Circle_axes` (missing), `[local] NDebugOverlay::Sphere_ang` (missing), `[local] NDebugOverlay::Clear` (missing), `[local] NDebugOverlay::LineAlpha` (missing), `[local] NDebugOverlay::ScreenRect` (missing), `[local] NDebugOverlay::ScreenLine_2color` (missing), `[local] NDebugOverlay::ScreenLine_1color` (missing), `NDebugOverlay::Cross3DOriented_ang` (bad), `NDebugOverlay::Cross3DOriented_mat` (bad)
- `Util:Vehicle_Fix` (5 of 25): `CBasePlayer::GetInVehicle [clone]` (missing), `CTFWeaponBaseGun::UpdatePunchAngles` (missing), `CPropVehicleDriveable::DriveVehicle` (missing), `CPropVehicleDriveable::PassengerShouldReceiveDamage` (missing), `CBaseCombatCharacter::CalculatePhysicsStressDamage` (missing)
- `Visualize:Blast_Radius` (1 of 4): `CEntitySphereQuery::CEntitySphereQuery [C1]` (missing)
- `Visualize:Dispenser_Radius` (1 of 1): `CObjectDispenser::DispenseThink` (missing)
- `Visualize:Flamethrower` (2 of 4): `CTFFlameEntity::Create` (missing), `CTFFlameEntity::RemoveFlame` (missing)
- `Visualize:Minigun_Deflect` (2 of 4): `CTFPlayer::IsMiniBoss` (missing), `CalcDistanceToLineSegment` (missing)
- `Visualize:Taunt_Attacks` (1 of 4): `CEntitySphereQuery::CEntitySphereQuery [C1]` (missing)

## Inlined functions and what the Windows build loses

Each was checked to have no standalone body on 11117211: the only Linux caller holds the inline, and the strings or the callee that would belong to a standalone copy appear once.

| Function | Inline in | Feature lost on Windows |
| --- | --- | --- |
| `CTFFlameManager::BCanBurnEntityThisFrame` | `OnCollide` 0x46eba0 (0x46ed22) | `Custom_Attributes` max_aoe_targets throttle on flamethrowers |
| `CTFPlayer::IsAllowedToInitiateTauntWithPartner` | `PlayTauntSceneFromItem` 0x506230 | `Custom_Attributes` always_allow_taunt |
| `CTFPlayer::MaybeDrawRailgunBeam` | `FireBullet` 0x51fe50 | `Weapon_Shoot` custom tracer particle and broadcast beam |
| `CTFBot::IsExplosiveProjectileWeapon` | `FireWeaponAtEnemy` 0x56a3c0 (as four `IsWeapon` calls) | `Improved_Targeting` close explosive attack cvar |
| `CTFPlayer::SpyDeadRingerDeath` | `OnTakeDamage` 0x500c70 | none: `Custom_Attributes` and `Human_Death_Yells` hook `FeignDeath` (0x4f0750) called with deathnotice true |
| `CTFWeaponBase::Energy_Recharge` | `IncrementAmmo` 0x636170 | none: `reload_full_clip_at_once` hooks `IncrementAmmo` |
| `CTFPlayer::ShouldDropAmmoPack` | `Event_Killed` 0x4ec3b0 | none: `Drop_Weapons` and `TFBot_Extensions` drop in an `Event_Killed` detour |
| `CTFBotMainAction::SelectCloserThreat` | `SelectMoreDangerousThreatInternal` | none: native body in `stub/tfbot_behavior.cpp` |

`CTFPlayer::UpdateExpression` is not inlined everywhere: 0x4f1dd0 is a standalone copy (stored as a function pointer at 0x4f6b75); `TFPlayerThink` (0x50faa0) also carries one inline, which the `Entity_Limit_Manager` detour does not reach.

`EconItemInterface_OnOwnerKillEaterEvent` was pinned to 0x48a4a0, which is the Batched wrapper; the non-batched interface body is 0x48a9f0 and 0x48a4a0 is now the Batched entry.

## Client-side only gaps

These hook the game client and have no meaning in a dedicated server: `Anim:EstimateAbsVelocity_MoveParent_Fix`, `Debug:Client_Desync`, `Debug:Sound_Leak`, `Etc:LaserDot_Fix`, `Etc:Override_Move_Speed`, `Prof:Debug_Overlay`, `Prof:Tier2_RenderUtils`, `Util:DebugOverlay_Font`, `Util:DebugOverlay_Font_v2`, `Util:DebugOverlay_Font_v3`, `Util:Notify_Recv`, `Util:Overlay_Enhancements`, `Util:Overlay_Recv`.

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

- AI (14): `EngieBot_Dispensers`, `EngieBot_NoPush`, `EngieBot_Wrangler`, `Focus_One_Player`, `Giant_Pyro`, `Improved_UseItem`, `My_Nextbot`, `My_Nextbot_Unlag`, `My_Nextbot_UnlagNPCGlobal`, `NextBotEventResponder_Hooks`, `Prevent_Postmortem_Updates`, `Puppet`, `RocketJump`, `WrapAssassin_AltFire`
- Anim (1): `Player_UpdateModel_AnimState_Fix`
- Attr (4): `BlockBackstab_OldStyle`, `CustomProjectileModel_Precache`, `HealOnKill_Overheal_Melee`, `Undocumented`
- Bot (9): `Bot_Player_Slot_Reorder`, `IsSpaceToSpawnHere_Scale`, `Kart_Locomotion`, `Kill_Before_ForceSpec`, `Medieval_NonMelee`, `MultiClass_Weapon`, `RunFast`, `Spy_MedicHeal`, `Spy_SelectRandomReachableEnemy`
- Canteen (1): `Share_Recall_Canteen`
- Common (4): `Commands`, `ExtraEntityData`, `Interrupt_Action`, `Text_Hud`
- Cond (2): `Enhanced_Cmds`, `Reprogrammed`
- Credits (2): `Better_Radius_Collection`, `Spawn_AutoCollect`
- Debug (49): `AirblastVuln`, `Backtrace`, `Better_Ent_Text`, `Bottle_Break`, `Building_Status`, `Client_Player_Track`, `Cond_Stunned`, `Conds`, `Console_Scramble_v1`, `Console_Scramble_v2`, `Console_Scramble_v2_PartA`, `Console_Scramble_v2_PartB`, `Credit_Magnet`, `Damage_Overlay`, `Deflect_Angle`, `Deflect_Angle_v2`, `Draw_CPhysCollide`, `EnergyRing_Knockback`, `FeignDeath_Ragdoll`, `Flamethrower_Impulse_101`, `Flamethrower_Misc`, `GetPlayerMaxSpeed`, `Grenade_Logger`, `Grenade_VPhysics`, `Heal_Debuff`, `IsPotentiallyTraversable_Trace`, `Max_Clients`, `Medigun_Speed`, `Melee_Trace`, `Minigun_State`, `MvM_Shield_FPS`, `Nav_Mesh`, `NextBot`, `NextBot_Input`, `NoKnockback`, `Owners`, `Parachute_Warp`, `Penetration`, `Proj_Energy_Ball`, `Projectile_Motion`, `Quantum_Duck`, `Rage`, `Revive_Exploit`, `SentryBuster_Mannhattan`, `Sticky_Detonation_Order`, `TF_Nav_Mesh_Trace`, `Tank_Destroy_Animation`, `Tele_AutoDetonate`, `TeleportWhere`
- Demo (1): `StringTable_Limit`
- Etc (33): `Allow_Civilian_Class`, `Crash_Fixes`, `CrayAirblast_ConVar_NoCheat`, `Deflect_Rocket_Spew`, `Detector`, `Entity_Limit_Manager_Convert_Serverside`, `Heat_Seeking_Rockets`, `Holiday_Items_Allow`, `Huntsman_Damage_Fix`, `Instant_Scaling`, `Limp_Projectiles`, `Loose_Cannon_Damage_Fix`, `MM_Spoof`, `Mapentity_Additions`, `Medicgun_Beam_Machinery`, `Melee_Ignore_Teammates`, `Misc`, `Misc:AllowVoteMidWave`, `Misc:HHHHealthBar`, `Misc:ScriptSaveLimit`, `Misc:SentryBusterParticleChange`, `Misc:SpectatorVoteFix`, `Nav_UpdateBlocked`, `Nav_UpdateBlocked_Visualize`, `Player_Bullet_Bounding_Fix`, `RateLimit_Exclude`, `SendProp_Override`, `SendProp_Override_Extension`, `Suppress_NB_Event_Messages`, `Target_ChangeGravity_Improved`, `Trigger_Filter_Fix`, `Unintended_Class_Weapon_Improvements`, `Weapon_Mimic_Teamnum`
- Item (1): `Item_Common`
- MvM (32): `Blu_Velocity_Limit_Remove`, `ChangeBotAttributes_Crash_Fix`, `ChangeClass_AnyTime`, `Chat_Unrestrict`, `Disposable_Dispenser`, `Disposable_Sentry_Health_Upgrades`, `Dominations`, `Explosive_Headshot_On_Everything`, `Extended_Upgrades`, `FriendlyFire`, `Gamemode_Converter`, `Gib_Improvements`, `JoinTeam_Blue_Allow`, `MedigunShield_Damage`, `No_Halloween_Souls`, `Player_Limit`, `Red_Robot_Eye_Glow`, `Refund_Exploit_Fix`, `RoboSapper_Override`, `Robot_Limit`, `Robot_Multiplier`, `Sapper_Allow_Multiple_Active`, `SentryBuster_Enhancements`, `Set_Credit_Team`, `Sub_Wave_Spawn_At_Once`, `Teleporter_Aggro`, `UpgradeStation_Regen_Improved`, `Upgrade_Disallow`, `Wave_Spawn_At_Once`, `Weapon_AntiGrief`, `Weapon_Balancing`, `YER_Unnerf`
- Perf (17): `:Func_Optimize`, `:Idle_Optimize`, `:Input_Optimize`, `:Virtual_Call_Optimize`, `Attributes_Optimize`, `Extra_Player_Slots`, `Extra_Player_Slots_Bots`, `Extra_Player_Slots_Players`, `Filesystem_Optimize`, `Flame_Breakable_Collision`, `HLTV_Client_Interact`, `Medigun_Shield_Damage_Events`, `Medigun_Shield_Damage_Interval`, `Medigun_Shield_Pathfinding`, `MvM_Load_Popfile`, `SmokeStack_FS_Thrash`, `Squad_Escort_Optimize`
- Pop (15): `ECAttr_Extensions`, `EventPopfile_Improvements`, `ExtAttr:AlwaysFireWeaponAlt`, `ExtAttr:IgnoreTargets`, `ExtAttr:Parse`, `ExtAttr:TargetStickies`, `KV_Conditional`, `Mission_Extensions`, `Nested_Complex_Spawners`, `PointTemplates`, `PopMgr_Extensions`, `TFBot_Extensions`, `Tank_Extensions`, `WaveSpawn_Extensions`, `Wave_Extensions`
- Prof (4): `Flame_Breakable_Collision`, `Frame_Prof`, `MvM_Shield_Events`, `Popfile_Load`
- Robot (7): `Building_Stomp`, `No_Canteens`, `Spawn_Protection_Fix`, `Spawn_SetName`, `Standable_Heads`, `Ticklish`, `Underground_Check_Override`
- Sniper (2): `Charge_Uncap`, `Head_Uncap`
- Sound (5): `Suppress_Giant_SentryBuster`, `Suppress_MedicBot_Shield`, `Tele_Activate`, `Unused_Credits`, `Unused_Sapper`
- Tank (1): `Gunslinger_Combo`
- Util (17): `Client_Cmds`, `ConFilter`, `Console_Recv`, `Console_Send`, `DTWarning_Use_CVar`, `Download_Manager`, `Entity_Overlays`, `ListenServerHost`, `Lua`, `Make_Item`, `Notify_Send`, `Pooled_String`, `Pooled_String_Fix`, `VProf_Recv`, `VProf_Send`, `VScript_Load_Init_Scripts`, `VScript_Send_Output_To_Admins`
- VGUI (1): `Test`
- Visualize (15): `Airblast_Box`, `Ammo_Counts`, `Backstab`, `Conds`, `Conds_Client`, `Damage_Force`, `Engie_Nests`, `Explosive_Headshot`, `Hitboxes`, `Huntsman`, `Jar_Radius`, `Melee_Range`, `Projectile_Speed`, `Projectile_Trail`, `Sapper_Range`

## Address names used by the code with no Windows entry

Names defined in `gamedata/sigsegv` and named in `src/`, with no entry in `windows.txt`, not resolved at run time, not `bad`: 442. Some are never reached on a dedicated server; the bed logs the ones a mission reaches (`unresolved functions called`). Grouped by class.

- `Action<CTFBot>` (5): `ApplyResult`, `BuildDecoratedName [clone]`, `InvokeOnEnd`, `InvokeOnResume`, `PrintStateToConsole`
- `Action<CZombie>` (5): `ApplyResult`, `BuildDecoratedName [clone]`, `InvokeOnEnd`, `InvokeOnResume`, `PrintStateToConsole`
- `Behavior<CTFBot>` (1): `FirstContainedResponder`
- `CAI_BaseNPC` (2): `GetActivityID`, `GetActivityName`
- `CAnimationLayer` (1): `StudioFrameAdvance`
- `CAttributeList` (4): `GetAttributeByID`, `GetAttributeByName`, `NotifyManagerOfAttributeValueChanges`, `SetRuntimeAttributeRefundableCurrency`
- `CAttributeManager` (4): `AddProvider`, `GetGlobalCacheVersion`, `IsProvidingTo`, `RemoveProvider`
- `CBaseAnimating` (15): `DrawServerHitboxes`, `FindBodygroupByName`, `GetAttachmentBone`, `GetBodygroup`, `GetBodygroupCount`, `GetBodygroupName`, `GetBoneTransform`, `GetModelPtr`, `GetNumBodyGroups`, `GetNumBones`, `GetPoseParameter [int]`, `GetPoseParameter [str]`, `InvalidateBoneCache`, `ResetSequenceInfo`, `SequenceDuration`
- `CBaseAnimatingOverlay` (9): `AddGesture`, `AddGestureSequence`, `FastRemoveLayer`, `FastRemoveLayer [clone]`, `GetLayerDuration`, `RemoveAllGestures`, `RemoveGesture`, `RestartGesture`, `SetLayerCycle`
- `CBaseClient` (3): `SendSnapshot`, `UpdateAcknowledgedFramecount`, `UpdateSendState`
- `CBaseCombatCharacter` (9): `CalcDamageForceVector`, `CalculatePhysicsStressDamage`, `IsAbleToSee [CBaseCombatCharacter *]`, `IsAbleToSee [CBaseEntity *]`, `IsGlowEffectActive`, `RemoveGlowEffect`, `SetAmmoCount`, `SetBloodColor`, `SwitchToNextBestWeapon`
- `CBaseCombatWeapon` (9): `ActivityOverride`, `CanPerformSecondaryAttack`, `Drop`, `GetMaxClip2`, `GetPrimaryAmmoType`, `GetShootSound`, `GetWpnData`, `Lower`, `OnActiveStateChanged`
- `CBaseEdict` (1): `GetChangeAccessor`
- `CBaseEntity` (22): `CalcAbsoluteVelocity`, `ClassMatchesComplex`, `EmitSound [member: normal + handle]`, `EmitSound [static: normal + handle]`, `GetDamageType`, `GetDataObject`, `GetModel`, `GetNextThink`, `GetTeamNumber`, `GetTouchTrace`, `IsBSPModel`, `PhysicsNoclip`, `PhysicsRunThink`, `PostClientActive`, `PrecacheSound`, `ReadKeyField`, `SetNextThink [index]`, `SetTransmitState`, `Spawn`, `TransformStepData_ParentToParent`, `TransformStepData_WorldToParent`, `VPhysicsInitStatic`
- `CBaseEntityOutput` (1): `ParseEventAction`
- `CBaseObject` (7): `FindBuildPointOnPlayer`, `FinishedBuilding`, `GetMiniBuildingStartingHealth`, `HasSapper`, `IsHostileUpgrade`, `MustBeBuiltOnAttachmentPoint`, `SetPlasmaDisabled`
- `CBasePlayer` (7): `DisableButtons`, `EnableButtons`, `ForceButtons`, `GetInVehicle [clone]`, `GetViewModel`, `SnapEyeAngles`, `UnforceButtons`
- `CBaseProjectile` (1): `CollideWithTeammatesThink`
- `CBaseServer` (5): `GetCPUUsage`, `GetClient`, `RejectConnection`, `RunFrame`, `UserInfoChanged`
- `CBaseViewModel` (4): `DestroyControlPanels`, `SetControlPanelsActive`, `SetWeaponModel`, `SpawnControlPanels`
- `CBeam` (2): `BeamCreate`, `EntsInit`
- `CCSBot` (3): `FindMostDangerousThreat`, `GetPartPosition`, `IsVisible`
- `CClientFrameManager` (2): `CountClientFrames`, `RemoveOldestFrame`
- `CCollisionProperty` (2): `MarkPartitionHandleDirty`, `SetSurroundingBoundsType`
- `CCurrencyPack` (2): `AffectedByRadiusCollection`, `DistributedBy`
- `CDownloadListGenerator` (1): `OnResourcePrecachedFullPath`
- `CEconEntity` (5): `DebugDescribe`, `GetAttributeContainer`, `GetAttributeManager`, `ReapplyProvision`, `UpdateBodygroups`
- `CEconItem` (1): `AddDynamicAttributeInternal`
- `CEconItemAttribute` (2): `CEconItemAttribute [C1]`, `GetStaticData`
- `CEconItemSchema` (1): `ItemTesting_CreateTestDefinition`
- `CEconItemView` (1): `GetSOCData`
- `CEconWearable` (3): `GetSkin`, `RemoveFrom`, `UnEquip`
- `CEntitySphereQuery` (1): `CEntitySphereQuery [C1]`
- `CEventQueue` (1): `AddEvent [EventQueuePrioritizedEvent_t *]`
- `CFrameSnapshotManager` (4): `CreatePackedEntity`, `GetPackedEntity`, `GetPreviouslySentPacket`, `UsePreviouslySentPacket`
- `CFuncNavCost` (1): `HasTag`
- `CFuncRotating` (1): `SetTargetSpeed`
- `CGameClient` (3): `GetSendFrame`, `SetupPackInfo`, `SetupPrevPackInfo`
- `CGameRules` (1): `IsConnectedUserInfoChangeAllowed`
- `CHLTVClient` (1): `SendSnapshot`
- `CHLTVDemoRecorder` (1): `StopRecording [clone]`
- `CItemGeneration` (1): `GenerateItemFromScriptData`
- `CMDLCache` (2): `BeginLock`, `EndLock`
- `CMannVsMachineStats` (3): `GetBottleSpending`, `GetBuyBackSpending`, `GetUpgradeSpending`
- `CMapListManager` (4): `GetMapCount`, `GetMapName`, `IsMapValid`, `RefreshList`
- `CModelLoader` (1): `FlushDynamicModels`
- `CMultiPlayerAnimState` (2): `OnNewModel`, `RestartGesture [clone]`
- `CNavArea` (2): `CollectAdjacentAreas`, `Contains`
- `CNavMesh` (2): `GetNavArea [ent]`, `GetNearestNavArea [ent]`
- `CNetChan` (5): `GetMaxRoutablePayloadSize`, `IsFileInWaitingList`, `IsValidFileForTransfer`, `SendNetMsg`, `SetFileTransmissionMode`
- `CNetworkStringTable` (1): `DeleteAllStrings`
- `CObjectDispenser` (1): `DispenseThink`
- `CObjectSapper` (1): `Spawn`
- `CObjectSentrygun` (1): `GetTurretAngles`
- `CParallelProcessor<CGameClient *>` (1): `Run`
- `CParallelProcessor<PackWork_t>` (1): `Run`
- `CPathTrack` (1): `GetNext`
- `CPlayer` (1): `GetEdict`
- `CPlayerInventory` (1): `GetItemByPosition`
- `CPopulationManager` (9): `AddRespecToPlayer`, `FindCheckpointSnapshot [CTFPlayer *]`, `FindOrAddPlayerUpgradeHistory`, `FindOrAddPlayerUpgradeHistory [CTFPlayer *]`, `GetPlayerUpgradeHistory`, `IsInEndlessWaves`, `LoadMvMMission`, `RemovePlayerAndItemUpgradesFromHistory`, `RemoveRespecFromPlayer`
- `CPropVehicleDriveable` (2): `DriveVehicle`, `PassengerShouldReceiveDamage`
- `CRConClient` (2): `BuildResponse`, `SendResponse`
- `CRecipientFilter` (1): `RemoveRecipientsByPVS`
- `CServerNetworkProperty` (2): `GetClassName`, `IsInPVS`
- `CServerRemoteAccess` (1): `SendVProfData`
- `CSoundEmitterSystemBase` (1): `InitSoundInternalParameters`
- `CStaticProp` (2): `GetEntityHandle`, `GetRefEHandle`
- `CStaticPropMgr` (5): `GetStaticProp`, `GetStaticPropIndex`, `IsStaticProp`, `LevelInit`, `LevelShutdown`
- `CSteamID` (1): `Render [static]`
- `CTFBall_Ornament` (1): `Create`
- `CTFBaseProjectile` (2): `GetDamage`, `SetDamage`
- `CTFBot` (19): `DelayedThreatNotice`, `ForgetSpy`, `GetBodyInterface`, `GetIntentionInterface`, `GetLocomotionInterface`, `GetTimeLeftToCapture`, `GetVisionInterface`, `IsExplosiveProjectileWeapon`, `IsKnownSpy`, `IsLineOfFireClear_ent`, `IsLineOfFireClear_vec`, `IsLineOfFireClear_vec_ent`, `IsSuspectedSpy`, `PushRequiredWeapon`, `RealizeSpy`, `StopSuspectingSpy`, `SuspectedSpyInfo_t::IsCurrentlySuspected`, `SuspectedSpyInfo_t::Suspect`, `SuspectedSpyInfo_t::TestForRealizing`
- `CTFBotFetchFlag` (1): `OnStart`
- `CTFBotMainAction` (4): `OnInjured`, `OnStart`, `ShouldAttack`, `ShouldHurry`
- `CTFBotMedicHeal` (1): `SelectPatient`
- `CTFBotProxy` (1): `CTFBotProxy [C1]`
- `CTFBotSniperLurk` (2): `SelectMoreDangerousThreat`, `ShouldAttack`
- `CTFBotUseItem` (1): `CTFBotUseItem [C1]`
- `CTFCompoundBow` (1): `GetCurrentCharge`
- `CTFFlameEntity` (2): `Create`, `RemoveFlame`
- `CTFFlameThrower` (1): `GetFlameOriginPos`
- `CTFGameRules` (4): `CanPlayerUseRespec`, `FlagsMayBeCapped`, `GetUpgradeTier`, `IsUpgradeTierEnabled`
- `CTFGrenadeLauncher` (1): `SecondaryAttack`
- `CTFInventoryManager` (1): `GetInventoryForPlayer`
- `CTFItem` (1): `GetItemID`
- `CTFKnife` (1): `IsBehindAndFacingTarget`
- `CTFMapsWorkshop` (2): `AddMap`, `Steam_OnUGCItemInstalled`
- `CTFMechanicalArm` (1): `ShockAttack`
- `CTFNavArea` (2): `AddPotentiallyVisibleActor`, `IsValidForWanderingPopulation`
- `CTFNavMesh` (1): `RecomputeInternalData`
- `CTFPipebombLauncher` (1): `SecondaryAttack`
- `CTFPlayer` (25): `AddObject [clone]`, `CanAttack`, `CanMoveDuringTaunt`, `DropFlag`, `ForceRegenerateAndRespawn`, `GetAttributeList`, `GetAttributeManager`, `GetDesiredHandScale`, `GetDesiredHeadScale`, `GetDesiredTorsoScale`, `GetHandScaleSpeed`, `GetHeadScaleSpeed`, `GetPassiveWeapons`, `GetTorsoScaleSpeed`, `HandleCommand_JoinTeam_NoMenus`, `HolsterOffHandWeapon`, `IsMiniBoss`, `MedicGetChargeLevel`, `PlaySpecificSequence`, `ReapplyPlayerUpgrades`, `RemoveAllCustomAttributes`, `RemoveInvisibility`, `RemoveObject`, `SetOffHandWeapon`, `StateTransition`
- `CTFPlayerShared` (7): `FindHealerIndex`, `GetConditionDuration`, `GetConditionsBits`, `GetPercentInvisible`, `IsLoserStateStunned`, `RecalculatePlayerBodygroups`, `SetDefaultItemChargeMeters`
- `CTFPointWeaponMimic` (1): `GetFiringAngles`
- `CTFPowerup` (1): `GetLifeTime`
- `CTFProjectile_Cleaver` (1): `Create`
- `CTFProjectile_EnergyBall` (1): `SetScorer`
- `CTFProjectile_EnergyRing` (1): `GetInitialVelocity`
- `CTFProjectile_Jar` (1): `Create`
- `CTFProjectile_JarGas` (1): `Create`
- `CTFProjectile_JarMilk` (1): `Create`
- `CTFReviveMarker` (2): `AddMarkerHealth`, `ReviveThink`
- `CTFSniperRifle` (2): `GetPenetrateType`, `SniperRifleChargeRateMod`
- `CTFSniperRifleDecap` (1): `GetCount`
- `CTFStunBall` (1): `Create`
- `CTFTeam` (1): `GetObject`
- `CTFTeamManager` (1): `IsValidTeam`
- `CTFWeaponBase` (13): `CanPerformSecondaryAttack`, `Energy_GetMaxEnergy`, `Energy_Recharge`, `GetEffectBarProgress`, `GetMaxHealthMod`, `GetProjectileFireSetup`, `GetSkin`, `GetTFPlayerOwner`, `GetTFWpnData`, `InternalGetEffectBarRechargeTime`, `Misfire`, `ShouldRemoveInvisibilityOnPrimaryAttack`, `WeaponReset`
- `CTFWeaponBaseGun` (2): `GetAmmoPerShot`, `UpdatePunchAngles`
- `CTFWearable` (1): `CanEquip`
- `CTFWorkshopMap` (1): `OnUGCItemInstalled`
- `CTakeDamageInfo` (1): `CTakeDamageInfo [C1 | overload 5]`
- `CTeamplayRoundBasedRules` (2): `GetNextRespawnWave`, `SetForceMapReset`
- `CThreadLocalBase` (1): `Get`
- `CUtlConstStringBase<char>` (1): `Set`
- `CVEngineServer` (3): `CheckAreasConnected`, `FindMap`, `GetChangeAccessor`
- `ILocomotion` (1): `TraceHull`
- `INextBot` (3): `DisplayDebugText`, `IsRangeGreaterThan`, `IsRangeLessThan`
- `NextBotGroundLocomotion` (1): `NextBotGroundLocomotion`
- `NextBotPlayer<CTFPlayer>` (1): `GetEntity`
- `PackWork_t` (1): `Process`
- `Path` (3): `BuildTrivialPath`, `ComputePathDetails`, `Optimize`
- `SVC_UserMessage` (2): `ReadFromBuffer`, `WriteToBuffer`
- `variant_t` (1): `SetOther`
- `(free functions)` (94): `AllocChangeFrameList`, `COM_CompressBuffer_LZSS`, `CRC_File`, `CalcDistanceToLineSegment`, `CheckMedicResist`, `CopyStringAttributeValueToCharPointerOutput`, `DispatchParticleEffect [overload 1]`, `DispatchParticleEffect [overload 4]`, `DispatchParticleEffect [overload 5]`, `ENTINDEX`, `EconItemInterface_OnOwnerKillEaterEvent_Batched`, `FindHullIntersection`, `FireEvent`, `GEconItemSchema`, `GameStringSystem`, `GetLoadoutPositionByName`, `GetParticleSystemNameFromIndex`, `GetPlayerClassData`, `InvalidateSharedEdictChangeInfo`, `InventoryManager`, `LookupWeaponInfoSlot`, `MapEntity_ParseToken`, `NET_SendLong`, `NET_SendPacket`, `NET_SendTo`, `NavAreaTravelDistance<CTFBotPathCost>`, `NextBotCreatePlayerBot<CTFBot>`, `PointInRespawnRoom`, `PrecachePointTemplates`, `SV_EnsureInstanceBaseline`, `SV_PackEntity`, `SV_ReplicateConVarChange`, `SendCvarValueQueryToClient`, `SendProxy_AngleToFloat`, `SendProxy_Color32ToInt`, `SendProxy_EHandleToInt`, `SendProxy_Empty`, `SendProxy_IntAddOne`, `SendProxy_LengthTable`, `SendProxy_QAngles`, `SendProxy_ShortAddOne`, `SendProxy_StringT_To_String`, `SendProxy_StringToString`, `SendProxy_UInt8ToInt32`, `SendProxy_VectorXYToVectorXY`, `SendTable_CullPropsFromProxies`, `SendTable_Encode`, `TE_BeamPoints`, `TE_BeamRingPoint`, `TE_BreakModel`, `TE_PhysicsProp`, `TE_PlayerDecal`, `TFInventoryManager`, `TheNextBots`, `ToTFBot`, `UTIL_GetCommandClient`, `UTIL_GetCommandClientIndex`, `UTIL_ParticleTracer`, `UTIL_PlayerDecalTrace`, `VProfRecord_Snapshot`, `VProfRecord_StartOrStop`, `V_vsnprintfRet`, `WeaponID_IsSniperRifleOrBow`, `WeaponIdToAlias`, `WriteRemoteVProfData`, `addrs`, `addrs_group`, `attribute_class`, `attribute_type`, `description_format`, `description_string`, `effect_type`, `g_BSPData`, `g_FrameSnapshotManager`, `g_MapListMgr`, `g_PropTypeFns`, `g_aClassNames`, `g_aTeamColors`, `g_arFakePorts`, `g_bUseFakeIP`, `g_nFakeIP`, `g_szPlayerRobotModels`, `lib`, `modelloader`, `name`, `net_blocksize`, `net_maxroutable`, `regex`, `s_StaticPropMgr`, `s_pTokenBuf`, `server`, `sigsegv`, `sv_maxroutable`, `sym`

Recorded `bad` (inlined, 14): `CAttributeList::AddAttribute`, `CBaseCombatWeapon::SetIdealActivity`, `CNetworkStringTable::UpdateMirrorTable`, `CTFFlameManager::BCanBurnEntityThisFrame`, `CTFPlayer::IsAllowedToInitiateTauntWithPartner`, `CTFPlayer::MaybeDrawRailgunBeam`, `CTFPlayer::ShouldDropAmmoPack`, `CTFPlayer::SpyDeadRingerDeath`, `CTFPlayer::UpdateExpression`, `CTFPointWeaponMimic::Fire`, `CWave::IsDoneWithNonSupportWaves`, `NDebugOverlay::Cross3DOriented_ang`, `NDebugOverlay::Cross3DOriented_mat`, `NextBotManager::CollectAllBots`.

## The four entries carry.py could not carry to 11117211

`overrides.json` held them at 11087207, so `emitgamedata.py` left them out of the 11117211 table.

| Entry | Result on 11117211 |
| --- | --- |
| `ConColorMsg` (tier0.dll) | unmoved at 0x45a0, still the `?ConColorMsg@@YAXABVColor@@PBDZZ` export |
| `_SpewMessage` (tier0.dll) | unmoved at 0x4bf0, still the callee of the exported `_SpewMessage` (0x6640) |
| `SQVM::Call` (vscript.dll) | unmoved at 0x2dfa0, only xref of the `SCRIPT PERF WARNING` string (0x2e138), `ret 0x14` |
| `CTFProjectile_BallOfFire::Burn` | 0x534bd0 (0 matches because the body changed): called from `RocketTouch` (0x5349c0), strings `Weapon_DragonsFury.BonusDamage`, `BonusDamageHit`, `BonusDamagePain`, `ret 4` |

The three library entries were byte-identical, so `carry.py`'s `unmoved` check should have kept them; the old binaries for 11087207 are no longer served, so they were re-read by hand. All four are in the table now (1,627 to 1,631 entries).
