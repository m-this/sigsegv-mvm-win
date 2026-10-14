# After IAddr_Sym::FindAddrWin, same build 24245063

The run that measured the one-line fix in `src/addr/standard.cpp`, against
`../20260918-build24245063/`.

| | before | after |
| --- | ---: | ---: |
| addresses OK | 1124 | 1125 |
| addresses FAIL | 1645 | 1644 |
| mods OK / FAILED | 10 / 23 | 10 / 23 |

`Msg` resolves, which is the whole of the gain and what the fix predicted:
tier0 exports it and the lookup was never tried.

Two datamap addresses swapped sides, `CTFTeamSpawn::m_DataMap` to OK and
`CFuncNavCost::m_DataMap` to FAIL. Those resolve through a runtime scan over
the entities the map has spawned, so they move between runs; the fix touches
`sym` entries only.
