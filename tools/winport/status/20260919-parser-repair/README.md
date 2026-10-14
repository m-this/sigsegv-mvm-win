# 14 addresses the gamedata parser was dropping on the floor

`classify.py` reads a `"name" "symbol"` pair inside an `addrs_group` as two
entries and gives both an empty symbol. `emitgamedata.py` already had a
fallback that re-reads those blocks, but it only added names it did not
already know, and the name *was* known: as an entry whose symbol is `""`,
which matches nothing.

So 131 entries carried no symbol, and the ones with a match sitting right
there failed anyway. The fallback now repairs a known entry with no symbol
instead of skipping it, and drops the bogus entry whose name is a mangled
symbol.

Measured on the Wine bed against `../20260919-corroborated/`:

| | before | after |
| --- | ---: | ---: |
| addresses OK | 1193 | 1208 |
| addresses FAIL | 1576 | 1561 |

The 14 recovered: `CAttributeList::IterateAttributes`,
`CEyeballBossDead::Update`, `CEyeballBossIdle::Update`,
`CGameMovement::FullNoClipMove`, `CGameMovement::PlayerMove`,
`CKickIssue::RequestCallVote`, `CLagCompensationManager::BacktrackPlayer`,
`CPlayerInventory::DumpInventoryToConsole`,
`CPlayerInventory::GetMaxItemCount`,
`CTeamplayRoundBasedRules::SetTeamRespawnWaveTime`,
`CTraceFilterIgnorePlayers::ShouldHitEntity`, `CZombieBehavior::OnKilled`,
`CZombiePathCost::operator()` and `SelectWeightedSequence`. Two datamaps
flipped with them, which they do between runs.

## A trap worth writing down

srcds under Wine takes the next port up when 27015 is still held, and the
first measurement of this change was taken from a server that was still
running with the old table on 27015 while the new one sat on 27016. Read the
`Network: IP ... ports N SV` line in `tf/console.log` and query that port.

One wineserver serves every wine process, so killing it by pid takes down
every server at once, not just the one meant.
