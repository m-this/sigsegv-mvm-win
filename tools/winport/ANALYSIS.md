# What still cannot work on Windows, and the batches that fix it

Status of the Windows port of SigMod, measured on 2026-09-18 against Steam
buildid 24245063 (ServerVersion 10828683, `tf/bin/server.dll` sha256
`0a2aade36a7b9dc1…`), and the work that is left, cut into batches an agent can
take one at a time. Every number below comes from a file in
`status/20260918-build24245063/`; re-measure before trusting any of them
against a newer game build.

The port loads, resolves 41 % of its address table, and plays `mvm_decoy`
under Wine with the archipelago plugin and the defender bots beside it. It has
also killed one player's real Windows server with `STATUS_HEAP_CORRUPTION`
before the first map loaded, and that crash has not been reproduced. Both are
true at once, and the second is why the launcher loads the mod only when a
mission asks for it.

## Rules for anybody working a batch

1. **Never guess an address.** A wrong address is a call into the wrong
   function: a crash if you are lucky, silent corruption if you are not. Every
   entry in `windows.txt` carries evidence, and `overrides.json` records four
   that were right and still had to be blocked. `FIELDS_MIN` in
   `emitgamedata.py:129` exists because two structural matches with no field
   evidence took a bisection to find. A gap is cheaper than a plausible wrong
   answer.
2. **Same build on both sides, or nothing means anything.** Linux vtable dumps
   from `server_srv.so` and Windows dumps from `server.dll` must come from the
   same `buildid` (`steamapps/appmanifest_232250.acf`). The stale dumps in
   `mvm-reversed/Useful/vtable` cost a week; see `README.md`.
3. **Measure, then change, then measure again.** The three `sig_list_*`
   commands over rcon are the instrument. A batch that does not end with a
   before/after diff of `sig_list_addrs` and `sig_list_mods` did not finish.
4. **Do not touch the Linux build.** Upstream's CI is the only thing that ships
   to Linux players. Every Windows change is behind `_MSC_VER` or `_WINDOWS`,
   or in `tools/winport/`.
5. **Wine is not Windows.** Wine's heap does not validate; the real one raised
   `0xc0000374`. A batch that "works under Wine" has cleared the floor, not the
   bar. Batch 9 is how the bar gets tested.
6. Keep the refusal discipline of `matchvtables.py`: a class whose two tables
   never agree in length gets no index from equal length, because equal length
   is the evidence.

## The instrument

Everything here was measured on the Wine bed. To reproduce:

```sh
# a Windows dedicated server, installed by SteamCMD with +@sSteamCmdForcePlatformType windows
export TF2_WIN_SERVER=$HOME/tf2-win-server WINEPREFIX=$HOME/.wine-tf2
tools/winport/run-wine-server.sh mvm_decoy          # xvfb-run + wine srcds.exe, log in tf/console.log
# wait for "Wave #1 initialized" in tf/console.log, then read tf/console.log's
# "Network: IP a.b.c.d ... ports N SV" line: rcon binds that address and port
RCON_HOST=a.b.c.d RCON_PORT=N tools/winport/rcon.py sig_list_addrs   > addrs.txt
RCON_HOST=a.b.c.d RCON_PORT=N tools/winport/rcon.py sig_list_mods    > mods.txt
RCON_HOST=a.b.c.d RCON_PORT=N tools/winport/rcon.py sig_list_linkage > linkage.txt
```

Two traps: the port goes up by one when 27015 is still held by a server that
did not die (`pkill -f 'wine srcds.exe'` between runs), and `+developer 2` does
not put `DevMsg` lines in `-condebug`'s log, so `IAddr::Init FAIL` is invisible
there; `sig_list_addrs` is the way to see it. `Warning()` lines do land in the
log: every `IHasDetours::LoadDetours: "<mod>" "<addr>" FAIL` is there.

To rebuild the extension: `OUT=/tmp/winport-build tools/winport/build.sh`
(clang-cl + lld-link, needs an xwin SDK and the AlliedModders checkout next
door; see `census.sh`). To regenerate the address table:
`emitgamedata.py matches.json 10828683 datamaps.json knownvtidx.generated.txt >
gamedata/sigsegv/windows.txt`.

## Where it stands

### The address table

`sig_list_addrs`: 2,769 entries, **1,124 OK, 1,645 FAIL**.

| FAIL by library | | FAIL by classifier bucket | |
| --- | ---: | --- | ---: |
| server | 1,372 | needs a scan (not in any vtable) | 937 |
| engine | 212 | virtual, in a dumped vtable | 449 |
| client | 33 | declared in code, not gamedata | 160 |
| dedicated, tier0, sourcemodcore, vguimatsurface | 5 each | C symbol, not mangled | 88 |
| vscript, soundemittersystem, datacache, vstdlib | 1–2 each | `sym regex` | 11 |

By how the gamedata asks for them: 695 `sym`, 35 `pattern`, 18 `fixed`, 9
`sym regex`, 11 `func ebpprologue *`, 2 `func knownvtidx`, 1 `sendtable`; the
rest are `IAddr` subclasses in `src/addr/*.cpp`.

By class, the server FAILs: free functions 185, `CTFPlayer` 108, `CTFBot` 51,
`CBaseEntity` 48, `CTFPlayerShared` 44, `CTFWeaponBase` 43,
`NextBotPlayer<CTFPlayer>` 32, `CTFGameRules` 31, `CBaseCombatWeapon` 29,
`NDebugOverlay` 27, `CPopulationManager` 26. `CTFPlayer` and `CTFBot` lead
because `matchvtables.py` refuses both: their vtables differ in length for real
(496 vs 490, 538 vs 495 slots), so none of their virtuals has an index.

### Detours, hooks, patches, thunks

`sig_list_mods`: 200 mods, **10 OK, 157 DISABLED, 23 FAILED, 10 UNLOADED**.
832 detours failed to load, and **every one of them failed because its target
address is FAIL** (0 resolved-yet-failed). So the detour mechanism itself
works on MSVC code once it has an address; the gap is the table.

`sig_list_linkage`, thunks with a null address: `MEMBER_FUNC` 380 of 762,
`STATIC_FUNC` 281 of 333, `GLOBAL` 72 of 102, `VIRTUAL_FUNC` 1 of 250. A null
thunk that is called ends the server with `SigMod: called unresolved function`
(`src/link/link.h:95`), which is the loud failure the port chose over a jump
to zero.

Patches: 35 `IHasPatches::LoadPatches … FAIL`. All 19 mods that carry byte
patches are FAILED, and none of their patches applied, which is the right
outcome: the bytes are GCC's codegen and would have patched the wrong
instruction if they had matched.

Virtual hooks: 7 FAIL, 3 of them in `Attr:Custom_Attributes` with an empty
name (`IHasVirtualHooks::LoadVirtualHooks: "Attr:Custom_Attributes" "" FAIL`),
which is a vhook whose class RTTI or vtable did not resolve.

### What the 99 missions actually use

`pop-feature-usage.json`, from the 99 SigMod pop files in the Potato and
Moonlight packs (all 99 found). Missions using each key:

| key | missions | lives in |
| --- | ---: | --- |
| `SpawnTemplate` | 73 | Pop:PointTemplates, Pop:PopMgr_Extensions |
| `PointTemplates` | 51 | Pop:PointTemplates |
| `NoRomevisionCosmetics`, `ForceHoliday`, `WaveStartCountdown`, `NoCritPumpkin`, `NoThrillerTaunt` | 23–53 | Pop:PopMgr_Extensions |
| `RobotLimit` | 28 | MvM:Robot_Limit |
| `ExtraSpawnPoint` | 23 | Pop:PopMgr_Extensions |
| `SniperAllowHeadshots`, `ImprovedAirblast`, `BodyPartScaleSpeed` | 17–21 | Pop:PopMgr_Extensions |
| `ExtraTankPath` | 17 | Pop:Tank_Extensions |
| `CustomWeapon`, `Upgrade`, `DisallowUpgrade`, `ExtendedUpgrades` | 11–16 | Attr:Custom_Attributes, MvM:Extended_Upgrades, MvM:Upgrade_Disallow |
| `CustomNavFile` | 16 | Pop:PopMgr_Extensions |
| `UpgradeStationKeepWeapons`, `SendBotsToSpectatorImmediately`, `FastNPCUpdate` | 13–15 | Pop:PopMgr_Extensions, Pop:TFBot_Extensions |
| `PlayerAttributes`, `AllowBotExtraSlots`, `MaxSpectators`, `BluPlayersAreRobots` | 12 | Pop:PopMgr_Extensions, Perf:Extra_Player_Slots |
| `LuaScriptFile` | 11 | Util:Lua |

And the state of those mods on Windows today:

| mod | status | detours | failed | notes |
| --- | --- | ---: | ---: | --- |
| Pop:PopMgr_Extensions | OK | 126 | 68 | loads, half its hooks missing: every key above that lives here runs on the half that resolved |
| Pop:PointTemplates | OK | 12 | 8 | `SpawnTemplate` in 73 missions rides on 4 of 12 hooks |
| Pop:TFBot_Extensions | DISABLED | 66 | 32 | |
| Pop:ECAttr_Extensions | DISABLED | 54 | 26 | |
| Pop:Tank_Extensions | DISABLED | 33 | 12 | `ExtraTankPath`, 17 missions |
| Pop:Wave_Extensions / WaveSpawn_Extensions | DISABLED | 18 / 30 | 7 / 6 | |
| Attr:Custom_Attributes | **FAILED** | 298 | 192 | `CustomWeapon` and custom `ItemAttributes`; the largest single gap |
| MvM:Extended_Upgrades | DISABLED | 12 | 7 | 11 missions |
| Util:Lua | OK | 30 | 8 | 11 missions |
| Etc:Mapentity_Additions | DISABLED | 67 | 38 | `PointTemplates` entities lean on it |
| Perf:Extra_Player_Slots | **FAILED** | 58 | 33 | `AllowBotExtraSlots`, `MaxSpectators`: 12 missions cannot have them |
| MvM:Robot_Limit | DISABLED | 6 | 3 | 28 missions |

"OK with failed detours" is the dangerous state: the mod announces itself and
the mission author's key parses, and part of the mechanic does nothing. That
is the same shape as apw-2v6 on the archipelago side.

### Things that cannot work as they are

Not "unresolved", but built on something Windows does not have.

1. **Byte patches, 19 mods** (`grep -l AddPatch src/mod`): `Sniper:Charge_Uncap`,
   `MvM:JoinTeam_Blue_Allow`, `MvM:Set_Credit_Team`, `Cond:Reprogrammed`,
   `Perf:Virtual_Call_Optimize`, `Perf:Func_Optimize`, `Bot:RunFast`, and the
   rest in `report.txt`. Each patch is a GCC instruction sequence with a mask,
   authored against `server_srv.so`. MSVC's codegen for the same function is a
   different sequence, so `Check` fails and the mod goes FAILED. Each needs the
   patch re-derived against `server.dll`, or the mod rewritten as a detour.
   None ships enabled in `cfg/sigsegv_convars.cfg`, so none blocks a mission.
2. **Function replacement** (`CFuncReplace`, `src/mem/patch.h:150`): sizes a
   replacement by the `__start_`/`__stop_` symbols GNU ld emits for a named
   section. MSVC has no equivalent, so it refuses to load. No mod in `src/mod`
   uses it today; leave it refused.
3. **`sym regex`, 11 entries**: a regular expression over the symbol table.
   There is no symbol table. Each needs reading on its own terms
   (`LibMgr::FindSymRegex`, `src/library.cpp:170`).
4. **Client-side symbols, 33 FAIL in `client` plus 47 names tagged
   `[client]`**: a dedicated server loads no `client.dll`. These serve the
   `visualize` and `vgui` mods on a listen server. Write them off for srcds.
5. **The 37 byte-pattern extractors** (`class CExtract_*` in `src/stub/*.cpp`
   and `src/addr/misc.cpp`): each reads a game function's bytes to pull a
   constant or an address out of an instruction. The `_WINDOWS` arms they
   carry are upstream's from years ago and were written against a
   `server.dll` that no longer exists; `src/addr/misc.cpp:56` already
   disables one for that reason. Every extractor that a Windows build reaches
   needs its Windows arm re-derived or replaced by an entry in `windows.txt`.
6. **GCC clones, 38 names tagged `[clone]`**: `.isra`, `.constprop` and
   `.part` clones exist only on the Linux side. The Windows target is the
   original function, and for some there is none: MSVC inlined
   `CAttributeList::GetAttributeByID` and `CTFWeaponBase::GetTFPlayerOwner`
   away (commit 4e06fd39), so the tree does their work itself on Windows.
   Each clone needs the same question asked.
7. **Datamaps**: the runtime scan (`src/addr/datamap`) fails on Windows, so
   `datamaps.py` resolves them statically into `datamaps.json` at emit time. A
   class it did not find has no datamap and no `datamap`-typed address.
8. **Linux-only code**, behind `#if !defined _WINDOWS`: `TRACE_DETOUR`
   wrappers (`src/mem/detour.h:290`), `Util:VProf_Remote`,
   `Util:DebugOverlay_Font_v3` (FAILED, 6 of 6), `Prof:*` perf counters,
   `firehose`. None matters to a mission; they stay off.

### Things that are unverified, which is worse

1. **119 reversed struct layouts** (88 `SIZE_CHECK` lines in `src/util/misc.h`
   users; apw-5g4.13). Every `sizeof` assert is a Linux number, so
   `SIZE_CHECK` checks nothing under `_MSC_VER`. `Action<CTFBot>`, `IBody`,
   `IVision`, `ILocomotion`, `INextBot`, `Path`, `PathFollower`, `ChasePath`,
   `CKnownEntity`, `CTFBotPathCost`, `EventChangeAttributes_t`,
   `CMannVsMachineUpgrades` and the `CTFBot*` behaviour classes are the ones a
   mission reaches. A stub whose MSVC layout differs reads and writes fields at
   the wrong offsets: exactly the shape of a heap corruption nobody can
   reproduce under Wine. **This is the leading candidate for the real Windows
   crash.**
2. **Member detours and `this`.** `DETOUR_DECL_MEMBER` on 32-bit Windows calls
   the original through a member pointer (`src/mem/detour.h:387`, `this` in
   `ecx`) where Linux passes it as the first stack argument. It works for most
   of the 58 active hooks in PopMgr_Extensions, and it does not for
   `CTFPlayer::ChangeTeam` ("its detour runs with a this that is not a player
   and faults in CheckPlayerClassLimit") or `CBasePlayer::ChangeTeam` ("the
   call from CTFPlayer::ChangeTeam lands in .data"); both are blocked in
   `overrides.json`. Nobody has explained why those two and not the others.
   The trampoline copies `Trampoline_CalcNumBytesToCopy` bytes of prologue
   (`src/mem/detour.cpp:36`) decoded with udis86; MSVC prologues with
   `mov edi,edi` hot-patch stubs, `jmp` thunks from incremental linking, or a
   function shorter than five bytes are the usual suspects.
3. **Calling conventions of static functions.**
   `AllocPooledString_StaticConstantStringPointer` is a free function on
   Linux and a member with the pool in `ecx` on Windows; including it "kills
   the server during a mission" (`overrides.json`). Every `STATIC_FUNC` thunk
   (333) that resolves is called with `__cdecl` and the Windows function may
   be `__thiscall`, `__fastcall` or `__stdcall`. Nothing checks.
4. **Vtable indices for `CTFPlayer` and `CTFBot`.** Refused by the matcher
   (rule 6), so 159 of their methods are FAIL rather than wrong. The 108 +
   51 are the largest class buckets in the table and most of what
   `Attr:Custom_Attributes` and `Pop:TFBot_Extensions` want.
5. **RTTI class-hierarchy walks on MSVC.** `CVirtualHookInherit` checks
   derivation through the MSVC class hierarchy descriptor (commit 9169fc3a)
   and `ActionStub` finds secondary vtables through the complete object
   locator. Both were written to compile, verified on the classes
   `mvm_decoy` reaches, and nothing else.
6. **Built with clang-cl, run against MSVC's engine.** SourceHook reads vcall
   thunks and only knows MSVC's shape, so `build.sh` patches a copy of
   SourceHook to read clang-cl's (`sourcehook-clang-cl-vcall-thunks.patch`).
   A build with real `cl.exe` would need the patch dropped again, and nobody
   has built one. `libs/fmt` is a guess at version 10.2.1 (apw-5g4.10).
7. **The engine's 212.** `engine.dll` FAILs: some are C exports resolvable by
   `GetProcAddress` and nobody has checked which (apw-5g4.6).

## The batches

Each batch is independent of the others unless it says so. Each ends with the
three `sig_list_*` dumps diffed against `status/20260918-build24245063/` and a
new directory under `status/` named by date and buildid. Sizes are addresses,
not hours.

### Batch 1: measure on real Windows (blocks nothing, informs everything)

Run the exact released package on a real Windows machine with heap checking
on, and get the crash into a debugger. Steps:

1. `gflags /p /enable srcds.exe /full` (page heap), or Application Verifier
   with Heaps checked. Run `srcds.exe -game tf -console -usercon +map
   mvm_decoy` with the extension installed. Page heap turns the corruption
   into an access violation at the instruction that writes out of bounds.
2. WinDbg attached, `sxe av`, `!analyze -v`, `k`. The faulting frame is in
   `sigsegv.ext.2.tf2.dll` or in `server.dll` called through a detour; either
   way it names the stub or the address.
3. Failing that, bisect `windows.txt`: the extension loads with what resolved
   and says what it lost, so halving the table is a valid experiment.

Also worth one run: `WINEDEBUG=warn+heap` under Wine with
`HKLM\System\CurrentControlSet\Control\Session Manager\GlobalFlag` set to
`0x02000000` (`FLG_HEAP_PAGE_ALLOCS`); Wine honours some of it. Cheaper than a
Windows box and unproven.

Output: a stack, and a bead on the archipelago side (apw-5g4.14) naming the
frame. If the frame is inside a stub, batch 2 goes first; if it is a detour,
batch 5.

### Batch 2: the struct layouts a mission reaches (~40 types)

For each type in the `SIZE_CHECK` list that `mvm_decoy` plus one SigMod
mission touches, measure the MSVC size and the offsets the stubs read:
`sizeof` from the class's constructor (`push`/`sub esp` and the allocation
size at its `operator new` call site), field offsets from the accesses in the
matched methods. Write a Windows value into `SIZE_CHECK` under `_MSC_VER`,
and the offsets into the stubs' `_WINDOWS` arms. Start with `INextBot`,
`IBody`, `IVision`, `ILocomotion`, `INextBotComponent`, `Action<CTFBot>`,
`Behavior<CTFBot>`, `Path`, `PathFollower`, `ChasePath`, `CKnownEntity`,
`CTFBotPathCost`, then the `CTFBot*` behaviours. Evidence per field: the
instruction that reads it, quoted in the commit.

Acceptance: `SIZE_CHECK` asserts non-trivially on `_MSC_VER` for every type
touched, and the server plays wave 1 of `mvm_decoy` and of one mission using
`SpawnTemplate` with no change in `sig_list_*`.

### Batch 3: `CTFPlayer` and `CTFBot` vtables (159 addresses)

Their Linux and Windows tables differ in length for real. Find the six slots
(`CTFPlayer`) and the forty-three (`CTFBot`) one side has and the other lacks.
Candidates named in `README.md`: covariant returns, which Itanium gives a
slot and MSVC does not; overload runs MSVC emits in reverse. Method: align
the two dumps by the functions batch 5's string evidence already matched on
both sides, and read the gaps between anchors. Every derived index goes into
`knownvtidx.generated.txt` with the anchor pair that proves it.

Acceptance: `matchvtables.py` emits `CTFPlayer` and `CTFBot` with a written
alignment, and `sig_list_addrs` shows the 159 as OK. Then `Pop:TFBot_Extensions`
and `Attr:Custom_Attributes` drop most of their failures.

### Batch 4: `Attr:Custom_Attributes` (191 failing detours)

The largest mod and the one `CustomWeapon` needs. Its 191 names are in
`failed_detours.tsv`. Take them by class: after batch 3 the `CTFPlayer*`
and `CTFBot` ones fall out; what remains is `CObjectSentrygun`,
`CObjectTeleporter`, `CObjectSapper`, `CTFProjectile_*`, `CTFWeaponBase*`,
`CAttributeList`, `CAttributeManager`. Each is a `matchfuncs.py` question:
unique string, then unique callee set, then a hand signature; `overrides.json`
with a `why` for each. The 3 empty-name vhook failures are a separate line:
find which `VHOOK_DECL` in `src/mod/attr/custom_attributes.cpp` has no class
resolved and why.

Acceptance: mod status OK, failed detours under 20, and a mission with
`CustomWeapon` (16 of the 99; `pop-feature-usage.json` names them) spawns
its weapons.

### Batch 5: the mission mods, in usage order (~230 addresses)

`Pop:PopMgr_Extensions` 68, `Etc:Mapentity_Additions` 38,
`Pop:TFBot_Extensions` 32, `Pop:ECAttr_Extensions` 26, `Pop:Tank_Extensions`
12, `Pop:PointTemplates` 8, `Util:Lua` 8, `MvM:Extended_Upgrades` 7,
`Pop:Wave_Extensions` 7, `Pop:WaveSpawn_Extensions` 6, `MvM:Robot_Limit` 3.
Names per mod in `failed_detours.tsv`. Same method as batch 4. Work
`PopMgr_Extensions` first: it is OK with half its hooks, which is the state
that lies to a mission author.

While here, decide the archipelago-side rule for a half-loaded mod: a mission
whose keys need a hook that did not resolve should be refused with the hook's
name, the way apw-2v6 asks for modifiers.

Acceptance: each mod OK with zero failed detours, and the missions that use
its keys play wave 1 under Wine.

### Batch 6: the two blocked detours and the static calling conventions

Explain `CTFPlayer::ChangeTeam` and `CBasePlayer::ChangeTeam`
(`overrides.json`, `bad: true`). Disassemble both prologues in `server.dll`
and the trampoline `CDetour` builds for them; compare with a detour that
works. Likely findings: a prologue udis86 splits mid-instruction, a
hot-patch `mov edi,edi`, or a `this` adjust in a thunk. Fix in
`src/mem/detour.cpp` with a test that detours both and calls them.

Then the 333 `STATIC_FUNC` thunks: for each resolved one, read the Windows
callee's convention from its `ret N` and its use of `ecx`/`edx`, and give
`DETOUR_DECL_STATIC_CALL_CONVENTION` / the thunk the right one.
`AllocPooledString_StaticConstantStringPointer` is the worked example.

Acceptance: the two `bad` entries leave `overrides.json`, and no static thunk
is called with a convention its target does not have.

### Batch 7: the engine and the free functions (212 + 185)

Check `engine.dll`'s export table first (`dumpbin /exports`, or
`pefile`): every C symbol it exports resolves through `GetProcAddress` with
no scan, and `LibMgr::FindSym` on Windows should try that before anything
else. Then the 185 free functions in `server.dll` (`report.txt`, "(free)"),
by unique string reference through `matchfuncs.py`. `TE_*` and
`GetParticleSystemNameFromIndex` are the ones a mission notices first: 16
`Link FAIL` lines each in the log.

Acceptance: engine FAILs under 50, with each remaining one written down as
unavailable and why.

### Batch 8: the 19 byte-patch mods and the 37 extractors

Only if a mission needs one. For a patch: find the function in `server.dll`
(it usually has a string), read MSVC's instruction, write the Windows patch
bytes and mask under `_WINDOWS` in the mod, keep the Linux ones. For an
extractor: same, into its `_WINDOWS` arm, replacing upstream's stale bytes.
`Perf:Func_Optimize` and `Perf:Virtual_Call_Optimize` are performance and can
stay FAILED forever; `Cond:Reprogrammed` and `MvM:Set_Credit_Team` are the two
a mission might ask for.

Acceptance: per mod, `LoadPatches` no longer fails and the mod's convar turns
it on without a crash.

### Batch 9: the 99 missions on Windows, against Linux (apw-5g4.12)

The bar. Same sweep as apw-5g4.11 on the Linux bed, against the Wine bed or a
real Windows machine, one wave each, then full clears on the maps carrying
the most missions. Output: a table, mission by mission, with the Windows
result beside the Linux one, and every difference traced to a name in
`sig_list_addrs`. This is the only cheap way to find what batches 3 to 7
missed.

### Batch 10: build hygiene (apw-5g4.3, apw-5g4.10)

Pin `libs/fmt` to a version and checksum the build fetches. Decide whether
the port ever builds with `cl.exe`; if it does, the SourceHook patch has to
become conditional. Move `build.sh` into CI on the fork so `package-windows.zip`
is built from a tag rather than a laptop.

## Reading the status files

- `sig_list_addrs.txt`: `<library>  <addr or FAIL>  <name>`. FAIL is the gap.
- `sig_list_mods.txt`: `Category Name Status Patches Detours D:Fail D:Act`.
  Status OK with D:Fail > 0 is a half-loaded mod.
- `sig_list_linkage.txt`: `KIND ADDRESS NAME`; address 0 is a thunk that
  ends the server if called.
- `failed_detours.tsv`: `<mod>\t<address name>`, from the `LoadDetours … FAIL`
  warnings, one line per pair.
- `report.txt`, `report2.txt`: the summaries the tables above were read from.
- `pop-feature-usage.json`: which SigMod keys the 99 missions use, counted.
