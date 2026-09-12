#!/usr/bin/env bash
# Run the Windows TF2 dedicated server under Wine, as a test bed for a Windows
# build of this extension.
#
# Three things are needed and none of them is obvious:
#
#   * srcds.exe is a GUI-subsystem PE, so Wine never gives it a console and
#     -console dies in CTextConsoleWin32::GetLine on
#     !GetNumberOfConsoleInputEvents. Flipping the subsystem byte to CUI on a
#     copy fixes that, and the copy is the only thing this script patches.
#   * without -console it draws its own dialog and waits for a click on Start
#     Server, forever.
#   * even in console mode it creates a window for the systray, so it needs a
#     display: headless it fails in nodrv_CreateWindow.
#
# How far this gets, on wine 10.0: the whole engine stack loads, engine.dll,
# materialsystem, studiorender, vphysics, datacache, vgui2, vscript and
# shaderapiempty. Then the process exits 255 without a word, before it loads
# tf/bin/server.dll.
#
# Three things say that wall is the engine and not the way it was started.
# srcds_win64.exe does exactly the same, so it is not a wine32 problem. Every
# map does the same, so it is not the map. And driving the GUI dialog instead,
# under Xvfb with xdotool pressing its default button, prints the same one
# shader line and exits the same way, so the dialog was never the blocker
# either. Do not spend another evening on the dialog.
#
# Nothing is hooked yet because server.dll is never mapped, so this is the wall
# to clear before the test bed is worth anything.
set -euo pipefail

SERVER="${TF2_WIN_SERVER:-$HOME/tf2-win-server}"
MAP="${1:-mvm_decoy}"
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine-tf2}"
export WINEDEBUG="${WINEDEBUG:--all}"

[ -d "$SERVER" ] || { echo "no server at $SERVER; set TF2_WIN_SERVER" >&2; exit 1; }
command -v xvfb-run >/dev/null || { echo "xvfb-run is required" >&2; exit 1; }

cd "$SERVER"
if [ ! -f srcds_cui.exe ] || [ srcds.exe -nt srcds_cui.exe ]; then
	python3 - <<'PY'
import struct, shutil
shutil.copy("srcds.exe", "srcds_cui.exe")
data = bytearray(open("srcds_cui.exe", "rb").read())
pe = struct.unpack_from("<I", data, 0x3C)[0]
at = pe + 24 + 68                      # OptionalHeader.Subsystem, PE32 and PE32+ alike
struct.pack_into("<H", data, at, 3)    # IMAGE_SUBSYSTEM_WINDOWS_CUI
open("srcds_cui.exe", "wb").write(data)
PY
	echo "patched srcds_cui.exe to the console subsystem"
fi

# script(1) is what gives the child a pty, which is what Wine turns into a
# console. Piping stdout instead leaves it with no console at all.
exec xvfb-run -a --server-args="-screen 0 1280x1024x24" \
	script -qec "wine srcds_cui.exe -game tf -console -condebug -nomessagebox \
		-nocrashdialog -nobreakpad +sv_lan 1 +maxplayers 6 +map $MAP" /dev/null
