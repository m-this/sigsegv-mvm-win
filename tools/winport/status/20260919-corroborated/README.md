# 68 addresses that the field-evidence gate was hiding

`corroborate.py` recomputed, for each of the 316 failing addresses whose match
`emitgamedata.py` refuses on weak field evidence, the evidence the match record
does not carry: shared string literals, and how much of the Linux function's
matched callee set the Windows candidate also calls.

111 of the 316 came back with evidence the gate could not see. 68 of those
cleared the bar used here and went into `overrides.json`, each with the
evidence in its `why`:

- 53 share at least one string literal with the Linux function and nothing in
  their callee set disagrees;
- 15 share no string but call every one of six or more matched callees.

Measured on the Wine bed against `../20260918-build24245063/`:

| | before | after |
| --- | ---: | ---: |
| addresses OK | 1124 | 1193 |
| addresses FAIL | 1645 | 1576 |
| failed detours | 852 | 785 |
| mods FAILED | 23 | 22 |

`mvm_decoy` still reaches wave 1 in 45 seconds. Per mod, the largest gains are
`Attr:Custom_Attributes` 192 to 174 failed detours, `Pop:PopMgr_Extensions` 68
to 61, `Etc:Mapentity_Additions` 38 to 32 and `Pop:TFBot_Extensions` 32 to 27.

`corroboration.txt` is the full run, including the 205 that carry no evidence
and the tiers that were left out: 12 more call 75% or better of four or more
matched callees, which is the next thing to try if these hold up.
