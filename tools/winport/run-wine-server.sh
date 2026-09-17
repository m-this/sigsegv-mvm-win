#!/usr/bin/env bash
# Run the Windows TF2 dedicated server under Wine, as a test bed for a Windows
# build of this extension.
#
# Three things are needed and none of them is obvious:
#
#   * do not touch srcds.exe. It is a GUI-subsystem PE, and the engine calls
#     AllocConsole() itself when it has no console, which Wine answers with a
#     real console on the display below. An earlier version of this script
#     patched the subsystem byte to CUI so the process would get a pty console
#     instead, and that is what caused the wall this bed sat behind for a week:
#     with a console already attached, the engine's AllocConsole fails, Wine's
#     console server dies with 0xc0000008, and srcds exits 255 without a word,
#     before tf/bin/server.dll is ever mapped.
#
#         WINEDEBUG=+console shows it:
#         0024:trace:console:alloc_console ()
#         0128:trace:console:process_console_ioctls failed to get next request
#
#   * it needs a display even in console mode, for the systray window, so it
#     runs under Xvfb. Headless it fails in nodrv_CreateWindow.
#
#   * Mann vs Machine refuses to host below 32 maxplayers and says so, then
#     sets sv_visiblemaxplayers to 6 itself. Ask for anything less and the map
#     load is abandoned after the game DLL is already up.
#
# -usercon is what opens the TCP listener rcon needs; without it the server
# answers on UDP only and every rcon connect is refused.
#
# How far this gets, on wine 10.0: the whole engine stack, tf/bin/server.dll,
# the map, MvM mode, and an rcon session. Output goes to tf/console.log through
# -condebug, because the console the engine allocated belongs to Wine.
set -euo pipefail

SERVER="${TF2_WIN_SERVER:-$HOME/tf2-win-server}"
MAP="${1:-mvm_decoy}"
RCON_PASSWORD="${RCON_PASSWORD:-winport}"
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine-tf2}"
export WINEDEBUG="${WINEDEBUG:--all}"

[ -d "$SERVER" ] || { echo "no server at $SERVER; set TF2_WIN_SERVER" >&2; exit 1; }
command -v xvfb-run >/dev/null || { echo "xvfb-run is required" >&2; exit 1; }
command -v wine >/dev/null || { echo "wine is required" >&2; exit 1; }

cd "$SERVER"
rm -f tf/console.log

echo "starting $MAP; watch $SERVER/tf/console.log, rcon on 27015"
exec xvfb-run -a --server-args="-screen 0 1280x1024x24" \
	wine srcds.exe -game tf -console -usercon -condebug \
		-nomessagebox -nocrashdialog -nobreakpad \
		+sv_lan 1 +rcon_password "$RCON_PASSWORD" \
		+maxplayers 32 ${DEVELOPER:+ +developer "$DEVELOPER"} +map "$MAP"
