# Adding addresses in groups, keeping only what still plays

The method that came out of two failed attempts to add addresses on paper
evidence alone.

## The filter

`/tmp/score.py`'s signals, computed per candidate against both binaries:

- is the candidate a function start at all;
- the ratio of the two function sizes, accepted between 0.4 and 2.5;
- string literals the two reference, shared and each side's excess;
- how much of the Linux function's matched callee set the candidate calls.

The size and string-excess checks are what the earlier attempts lacked.
`Script_StringToFile` is the example: 133 bytes on Linux, 9,552 on Windows,
and 44 strings the Linux function never mentions. It is not the same
function, it is the caller that inlined it, and it was in the 19 leads that
stopped the server.

## The sweep

A filter is still not proof, so candidates go in four at a time, the table is
rebuilt and `mvm_decoy` is played. A group that fails is reverted and the next
is tried, so one wrong address costs its group rather than the whole set.

| round | candidates | kept | dropped |
| --- | ---: | ---: | ---: |
| scored leads and vtable cross-checks | 32 | 30 | 2 |
| widened leads | 8 | 8 | 0 |

The two dropped are `CTFGCServerSystem::PreClientUpdate` and
`CTFGameRules::BroadcastSound`, isolated by bisecting their group of four.

## Result

Played with the archipelago plugin, the defender bots and SigMod loaded:

| map | wave 1 | addresses OK | unresolved calls |
| --- | --- | ---: | ---: |
| `mvm_decoy` | yes | 1245 | 0 |
| `mvm_deathpour_rc1` (community, SigMod expert) | yes | 1244 | 0 |
| `mvm_mannworks` | yes | 1244 | 0 |

Over the day, 1124 resolved to 1245, and overrides 36 to 142.

## One map still refuses, and it is worth writing down

`mvm_skeleclipse_b7a` ends with

    SigMod: called unresolved function "CEconItemSchema::GetItemDefinitionByName"

which is the designed loud failure rather than a crash. The function is a
23-byte thunk with no strings, so no string route reaches it. Eighteen matched
callers vote for one Windows address, 0x3b8810, twenty times between them,
and the Linux body null-checks its argument and tail-jumps to the real lookup
while that candidate is `call; add eax, 4; ret`. Adding it does silence the
unresolved call and the map then dies a different way, on

    "???" detour validation failure!

so the address is wrong, or right and too small to detour. It is not in the
table. A mission that needs it cannot be played on Windows yet.
