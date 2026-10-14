# 19 string leads, and the test that rejected them

`leads.py` asks, for an address with no match at all, which Windows functions
reference the same string literals as the Linux one. These 19 each had exactly
one unclaimed candidate referencing two or more of their strings, with no
other wanted address claiming the same candidate. On paper that is the
evidence `matchfuncs.py` calls a string match.

Merged into `windows.txt` and play-tested:

| table | outcome |
| --- | --- |
| 104 overrides, 931 addresses | `mvm_decoy` reaches wave 1 |
| plus these 19, 950 addresses | map loads, server shuts down, no wave |
| plus the first ten only | the same |

So at least one of the first ten is wrong. Which one is not known: the bed
became unreliable under repeated restarts before the bisection finished, and
the remaining rounds are the work to pick up.

The lesson is the same one the vtable candidates taught, and it is now twice
measured: evidence that looks conclusive on paper is not a substitute for
starting the server. Every address added to `windows.txt` in this session that
did survive that test went in one batch of 68 and one of 14, each play-tested
before it was committed.

`candidates.txt` keeps them with their strings, for the per-address reading
that would settle each one.
