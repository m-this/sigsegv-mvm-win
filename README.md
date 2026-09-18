# sigsegv-mvm, the Windows port

This is [rafradek/sigsegv-mvm](https://github.com/rafradek/sigsegv-mvm), the
SourceMod extension behind most community Mann vs Machine missions, built for
a Windows dedicated server. Upstream ships Linux only, and its answer for
Windows is a WSL virtual machine. This fork builds `sigsegv.ext.2.tf2.dll`.

It exists for [tf2-archipelago](https://github.com/m-this/tf2-archipelago),
whose Windows launcher installs the release from here so that missions which
need SigMod can be played on a Windows host. Everything upstream does on
Linux is unchanged in this tree; the port lives behind `_MSC_VER` and
`_WINDOWS`, and in `tools/winport/`.

## State

It loads, and it plays. It is not finished, and the launcher that installs it
loads it only while a mission asks for it, for that reason.

- The extension resolves **41 %** of its address table on Windows: 1,124 of
  2,769 addresses, measured 2026-09-18 against Steam buildid 24245063.
- Of 200 mods, 10 load fully, 23 fail, and the rest are off by default. The
  mission-facing ones (`PopMgr_Extensions`, `PointTemplates`, `Lua`) load
  with about half their hooks.
- `mvm_decoy` plays under Wine with the tf2-archipelago plugin and the
  defender bots loaded beside it. One player's real Windows server died with
  `STATUS_HEAP_CORRUPTION` before its first map, and that has not been
  reproduced.

**[`tools/winport/ANALYSIS.md`](tools/winport/ANALYSIS.md)** is the whole
picture: what cannot work on Windows and why, what is unverified, and the
work cut into batches with acceptance tests. Read it before changing anything.
`tools/winport/README.md` explains how the address table is derived.
`tools/winport/status/` holds the measurements each claim above was read from.

## How the port works

Linux `server_srv.so` keeps its symbol table and SigMod finds every game
function by name. Windows `server.dll` is stripped, so the port gives each
Linux symbol a Windows address in `gamedata/sigsegv/windows.txt`, generated
by `tools/winport/emitgamedata.py` from three sources:

- **vtable matching**: MSVC's RTTI names every class, so both platforms'
  vtables can be dumped from the same game build and aligned
  (`dumpvtables.py`, `dumplinuxvtables.py`, `matchvtables.py`);
- **function matching**: a function alone in referencing a string on both
  sides is the same function, and its callees follow (`matchfuncs.py`);
- **hand-checked overrides** with a written reason each
  (`tools/winport/overrides.json`).

`windows.txt` loads first and the first entry under a name wins, so the
`AddrManager::Load: duplicate addr` lines on every start are by design.

## Build

From Linux, with clang-cl and lld-link against an xwin SDK:

```sh
OUT=/tmp/winport-build tools/winport/build.sh
```

See `tools/winport/census.sh` for what it needs. Releases are tagged by date
and carry `package-windows.zip`, which tf2-archipelago pins by SHA-256 in
`deploy/env/versions.env`.

## Test bed

A Windows dedicated server under Wine, driven by
`tools/winport/run-wine-server.sh`, read through `tools/winport/rcon.py`.
Wine's heap does not validate the way Windows' does: passing there is the
floor, not the bar.

## Upstream

Everything that is not the port is rafradek's and sigsegv's work, under the
licence in `LICENSE`. The wiki and the Linux packages are at
[rafradek/sigsegv-mvm](https://github.com/rafradek/sigsegv-mvm); upstream's
own README follows for reference.

---

# sigsegv-mvm (upstream README)

gigantic, obese SourceMod extension library of sigsegv's and rafradek's TF2/Source mods (mostly MvM related)
For other Source games, only optimize-only package is provided

# Tips

How to run a TF2 server on Windows using WSL: https://github.com/rafradek/sigsegv-mvm/wiki/Installing-on-Windows-with-WSL
# Features
### Optimize-Only Package
* Reduce server cpu usage by ~50%
* [A list of all configurable features](https://github.com/rafradek/sigsegv-mvm/blob/master/cfg/sigsegv_convars_optimize_only.cfg)
### No-MvM Package
* Reduce server cpu usage by ~50%
* Extra player slots
* Interact with SourceTV spectators
* Reduce the amount of networked entities and automatically remove disposable entities when the entity limit is met
* [Hundreds of new attributes](https://sigwiki.potato.tf/index.php/List_of_custom_attributes)
* [New entity inputs, outputs and keyvalues](https://sigwiki.potato.tf/index.php/Entity_Additions)
* [A list of all configurable features](https://github.com/rafradek/sigsegv-mvm/blob/master/cfg/sigsegv_convars_no_mvm.cfg)
### Full Package
* All features from above
* More popfile features documented in [demonstrative popfile](https://github.com/rafradek/sigsegv-mvm/blob/master/scripts/mvm_bigrock_sigdemo.pop) and [wiki](https://sigwiki.potato.tf/)
* [A list of all configurable features](https://github.com/rafradek/sigsegv-mvm/blob/master/cfg/sigsegv_convars.cfg)

# Installing
Download a package (optimize-only, no-mvm, or full) from releases and extract it into server tf directory. Edit cfg/sigsegv_convars.cfg to enable or disable features

# How to build

This extension requires gcc 13 to build

Ubuntu 20.04 docker image with gcc 13 and other dependencies already installed (skip to step 3): rafradek/ubuntu2004dev:latest 

On Ubuntu 24.04:

1. Add x86 architecture if not installed yet
```
dpkg --add-architecture i386
apt update
```

2. Install packages:
```
autoconf libtool pip nasm libiberty-dev libiberty-dev:i386 libelf-dev:i386 libboost-dev:i386 libbsd-dev:i386 libunwind-dev:i386 lib32z1-dev libc6-dev-i386 linux-libc-dev:i386 g++-multilib
```

3. Clone Sourcemod, Metamod, SDK repositories, and AMBuild
```
cd ..
mkdir -p alliedmodders
cd alliedmodders
git clone --recursive https://github.com/alliedmodders/sourcemod --depth 1 -b 1.11-dev
git clone https://github.com/alliedmodders/hl2sdk --depth 1 -b sdk2013 hl2sdk-sdk2013
git clone https://github.com/alliedmodders/hl2sdk --depth 1 -b tf2 hl2sdk-tf2
git clone https://github.com/alliedmodders/hl2sdk --depth 1 -b css hl2sdk-css
git clone https://github.com/alliedmodders/metamod-source --depth 1 -b 1.11-dev
git clone https://github.com/alliedmodders/ambuild --depth 1
```

4. Install AMBuild. Also add ~/.local/bin to PATH variable (Not needed if ambuild is installed as root)
```
pip install ./ambuild
echo 'export PATH=~/.local/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

6. Init submodules:
```
cd ../sigsegv-mvm
git submodule init
git submodule update --depth 1
cd libs/udis86
./autogen.sh
./configure --enable-static=yes
make CFLAGS="-m32" LDFLAGS="-m32"
mv libudis86/.libs/libudis86.a ../libudis86.a
make clean
make CFLAGS="-fPIC"
mv libudis86/.libs/libudis86.a ../libudis86x64.a
cd ../..
```

7. Install lua:
```
cd libs
wget https://www.lua.org/ftp/lua-5.4.4.tar.gz
tar -xf lua-*.tar.gz
rm lua-*.tar.gz
mv lua-* lua
cd lua
make CC=g++ MYCFLAGS='-m32 -DLUA_USE_LONGJMP' MYLDFLAGS='-m32'
mv src/liblua.a ../liblua.a
make clean
make CC=g++ MYCFLAGS="-fPIC -DLUA_USE_LONGJMP"
mv src/liblua.a ../libluax64.a
cd ../..
```

9. If hl2sdk, metamod, sourcemod directory is placed in a custom location, Update autoconfig.sh with correct paths

10. Run autoconfig.sh

11. Build

Release:
```
mkdir -p build/release
cd build/release
ambuild
```

Debug (libbsd-dev:i386 libunwind-dev:i386 is required to load the extension):
```
mkdir -p build
cd build
ambuild
```
Build output is created in the current directory

Build and create full, no-mvm, optimize-only packages (they can be found in build/release):
```
./multibuild.sh
```
