# Porting the address table to Windows

SigMod finds game functions by symbol. Linux `server_srv.so` keeps its symbol
table, so `LibMgr::FindSym` (`src/addr/standard.cpp:10`) resolves a mangled name
straight to an address. Windows `server.dll` is stripped, so those lookups return
nothing and the extension would load having hooked nothing at all.

That is the whole reason there is no Windows build, and `src/addr/TODO-win.txt`
is the note left when the attempt stopped.

## What the address table actually contains

`classify.py` parses all 35 files under `gamedata/sigsegv`, demangles every
symbol, and looks each one up in `mvm-reversed/Useful/vtable`, which holds dumps
of 3,103 Linux vtables already in this repository.

    python3 tools/winport/classify.py .

2,985 address entries, by type:

| type                 | count | resolves without symbols? |
| -------------------- | ----: | ------------------------- |
| `sym`                | 2,579 | no                        |
| `func knownvtidx`    |   263 | yes                       |
| `pattern`            |    42 | yes                       |
| `datamap`            |    30 | yes                       |
| `func ebpprologue *` |    32 | yes                       |
| `fixed`              |    20 | yes                       |
| `sym regex`          |    11 | no                        |
| `convar`             |     7 | yes                       |

395 already work anywhere. **2,590 do not.** The 263 `func knownvtidx` entries
matter out of proportion to their count: they prove the mechanism, the gamedata
syntax and the loader path are all already in place.

## The 2,590, by how hard each one is

| bucket                     | count | route                                  |
| -------------------------- | ----: | -------------------------------------- |
| virtual, found in a vtable |   970 | `func knownvtidx`, no signature at all |
| not in any vtable          | 1,294 | `pattern` or an `ebpprologue` strategy |
| non-mangled C symbols      |   315 | data globals and engine exports        |
| `sym regex`                |    11 | case by case                           |

## The dumps have to come from the same build

The Linux tables under `mvm-reversed/Useful/vtable` were made against some past
build and say so nowhere. Against a current `server.dll` they disagree for
reasons that look like the ABI and are not: `CGenericFlexCycler` has a single
vtable on each side and still differed by ten slots, which no ABI rule explains
and a game update does.

`dumplinuxvtables.py` is the answer, and it needs no reversing at all.
`server_srv.so` keeps its symbol table, which is the whole reason SigMod
resolves anything on Linux: `_ZTV<class>` is the vtable and every slot in it
points at a function the symbol table names. It reads the sub-table structure
too, since an Itanium vtable opens each one with its offset-to-top and its
typeinfo pointer, so a class that multiply inherits comes out table by table
rather than as one flat run that walks on into its bases.

    python3 tools/winport/dumplinuxvtables.py /path/to/tf/bin/server_srv.so linux-vtables/

3,277 classes, 238,617 slots, from the same build as the Windows dump. Check
that: `steamapps/appmanifest_232250.acf` on each side carries a `buildid`, and
the two have to be equal or none of this means anything.

Matching the fresh dump instead of the stale one took the resolved count from
**214 to 388**, and it moved the alignment used from `raw` to `collapse` for 99
classes, which is the Itanium double destructor showing up exactly where it
should.

## What is done

`dumpvtables.py` reads the MSVC RTTI out of `server.dll` directly, no IDA
licence needed. MSVC puts a Complete Object Locator immediately before every
vtable and the locator names the class, which is the one thing stripping leaves
behind. On the current build it recovers **3,991 vtables across 3,150 classes**.

    python3 tools/winport/dumpvtables.py /path/to/tf/bin/server.dll win-vtables/

`matchvtables.py` aligns a Linux dump against its Windows twin. The two ABIs
differ in two ways that matter: Itanium emits two destructor slots where MSVC
emits one, and MSVC reverses a run of overloads declared together. Which applies
is not recorded anywhere, so it tries each combination and keeps the one that
makes the tables equal in length.

    python3 tools/winport/matchvtables.py \
        mvm-reversed/Useful/vtable/server_srv win-vtables/ classified.json

Both dumps now carry the offset of each sub-table, so a class that multiply
inherits is compared table for table: the one at offset 0 is the class's own on
either side. That refusal bucket is gone, and what it was hiding is visible
instead, which is that some classes genuinely have a different number of
virtuals on the two platforms.

Result on the current build, against a version-matched Linux dump, and it is
deliberately conservative:

| outcome                  | addresses | classes |
| ------------------------ | --------: | ------: |
| index derived            |       388 |     108 |
| no alignment fits        |       408 |     104 |
| no dump on one side      |       174 |      63 |

`knownvtidx.generated.txt` holds those 206. Every one was checked back against
both dumps: 201 entry names match their signature exactly and the other five are
the gamedata's own overload spellings (`[Vector]`, `IsAbleToSee2`,
`BConvertStringToEconAttributeValue`), each landing on the right overload.

Equal length is evidence, not proof. It is strong for a class with one vtable
and worth nothing for one with several, so a class MSVC gave more than one
vtable is refused outright rather than guessed at. A wrong vtable index is a
call into the wrong function: a crash if you are lucky, silent corruption if you
are not. A gap somebody fills by hand costs far less.

## Two traps, both already paid for

A symbol in `gamedata/sigsegv` is written across a line break, so its value
carries a newline and four tabs. Fed to `c++filt` that produces one output line
more than there were inputs, and every name after it is attributed to the wrong
address. `demangle()` now strips whitespace and refuses on a line-count
mismatch instead of zipping the two lists together.

Walking a vtable until the first non-code pointer runs straight into the next
class, because `.rdata` packs them together and the neighbour's first slot is a
code pointer too. Every table is preceded by its own locator, so the locator
addresses are the boundaries.

## Order of work from here

1. The 408 that do not align. These are no longer a tooling gap: both sides are
   the same build and the same sub-table, so a class whose tables differ in
   length differs for real. `CTFPlayer` is 496 against 490, `CTFBot` 538 against
   495. Find what the six or the forty-three are on one class and the answer
   probably covers many: candidates are covariant returns, which Itanium gives a
   slot and MSVC does not, and overload runs MSVC reverses.
2. Make AMBuild's MSVC path build. `AMBuildScript` already has
   `configure_msvc` and `configure_windows`; what has never been tried is
   `libs/udis86` and `libs/lua`, both built with autotools by the Linux CI.
3. Load it with 206 + 263 addresses resolved and everything else failing
   loudly, so the remaining gap is measured rather than estimated.
4. Work the 1,294 in batches, cheapest strategy first: unique string reference,
   unique convar reference, unique call site, then hand-written signatures.

Steps 1 and 2 are independent. Step 3 is the first point at which anything is
testable at all.
