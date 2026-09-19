# 164 vtable candidates, and why they are not in the table

`alignprimary.py --candidates` produced these on 2026-09-19 against build
24245063: an index for every currently failing address that sits at a slot two
agreeing anchors bracket, in a class the interface-override drop brings to
equal length.

They were merged into `windows.txt` and run. The result:

| table | outcome |
| --- | --- |
| as it stands | wave 1 of `mvm_decoy` in 45 s |
| plus these 164 | map loads, then the server shuts itself down, twice |

So at least one is wrong. 163 of the 164 come from a class that has a
disagreeing anchor somewhere in it; exactly one comes from a class where every
anchor agrees.

Kept because the list is where per-address verification should start: each row
carries the class, the index, the Windows address and how many anchors agree
in that class. What it is not is a fragment to ship.
