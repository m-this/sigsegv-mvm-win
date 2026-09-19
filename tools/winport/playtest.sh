#!/usr/bin/env bash
# Play one mission on the Wine bed and say what the extension did.
#
# The bed is run-wine-server.sh; this drives it, waits for the map, asks the
# server what resolved, and reports. One run per invocation, because one
# wineserver serves every wine process on the machine and two beds share it.
#
#     tools/winport/playtest.sh mvm_decoy
#     tools/winport/playtest.sh mvm_deathpour_rc1 mvm_deathpour_rc1_int_technical_terror
#
# Writes a directory under $OUT (default /tmp/playtest) per run: the console
# log, the three sig_list dumps, and result.txt.
#
# Two traps this handles, both of which have produced a wrong measurement:
#   * srcds takes the next port up when 27015 is held, so the port is read from
#     the "Network: IP ... ports N SV" line rather than assumed;
#   * srcds binds rcon on the machine's LAN address, not loopback.
set -uo pipefail

MAP="${1:?usage: playtest.sh MAP [POPFILE]}"
POP="${2:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER="${TF2_WIN_SERVER:-$HOME/tf2-win-server}"
OUT="${OUT:-/tmp/playtest}/${MAP}${POP:+.$POP}"
WAIT="${WAIT:-420}"
PYTHON="${PYTHON:-$HOME/winport-deps/venv/bin/python}"
LOG="$SERVER/tf/console.log"

mkdir -p "$OUT"
rm -f "$LOG"

# A leftover server holds the port and answers rcon, which is how a previous
# measurement came from the wrong build entirely.
for pid in $(pgrep -f 'wine srcds' || true); do kill "$pid" 2>/dev/null; done
sleep 3

echo "== $MAP${POP:+ / $POP}"
nohup "$ROOT/tools/winport/run-wine-server.sh" "$MAP" > "$OUT/runner.out" 2>&1 &
runner=$!

waited=0
until grep -q 'Network: IP' "$LOG" 2>/dev/null || [ "$waited" -ge "$WAIT" ]; do
	sleep 5; waited=$((waited + 5))
done
port=$(sed -n 's/.*ports \([0-9]*\) SV.*/\1/p' "$LOG" | head -1)
host=$(sed -n 's/.*Network: IP \([0-9.]*\).*/\1/p' "$LOG" | head -1)
[ -n "$port" ] || { echo "   the server never announced a port"; echo "no-port" > "$OUT/result.txt"; exit 1; }
echo "   rcon $host:$port"

# The map is up when a wave is initialised. A mission asked for by name needs
# tf_mvm_popfile and a reload, which starts the wait again. The convar takes the
# mission name alone: given a path it answers "Could not find a valid population
# file matching" and leaves the map on its own mission, which reads as a pass.
wait_for_wave() {
	local seen=$1 n=0
	until [ "$(grep -c 'Wave #1 initialized' "$LOG")" -gt "$seen" ] \
		|| ! pgrep -f 'wine srcds' >/dev/null || [ "$n" -ge "$WAIT" ]; do
		sleep 5; n=$((n + 5))
	done
}
wait_for_wave 0
waves=$(grep -c 'Wave #1 initialized' "$LOG")

if [ -n "$POP" ] && [ "$waves" -gt 0 ]; then
	echo "   loading $POP"
	RCON_HOST="$host" RCON_PORT="$port" "$PYTHON" "$ROOT/tools/winport/rcon.py" \
		"tf_mvm_popfile $POP" > "$OUT/popfile.txt" 2>&1
	wait_for_wave "$waves"
fi

alive=no; pgrep -f 'wine srcds' >/dev/null && alive=yes
if [ "$alive" = yes ]; then
	for cmd in sig_list_addrs sig_list_mods sig_list_linkage; do
		RCON_HOST="$host" RCON_PORT="$port" "$PYTHON" "$ROOT/tools/winport/rcon.py" \
			"$cmd" > "$OUT/$cmd.txt" 2>&1
	done
fi
cp "$LOG" "$OUT/console.log" 2>/dev/null

ok=$(awk 'NF>=3 && $2!="FAIL" && $2!="ADDRESS"' "$OUT/sig_list_addrs.txt" 2>/dev/null | wc -l)
fail=$(awk '$2=="FAIL"' "$OUT/sig_list_addrs.txt" 2>/dev/null | wc -l)
modok=$(awk '$3=="OK"' "$OUT/sig_list_mods.txt" 2>/dev/null | wc -l)
modfail=$(awk '$3=="FAILED"' "$OUT/sig_list_mods.txt" 2>/dev/null | wc -l)
popfile=$(sed -n 's/.*Wave #1 initialized of mission \(.*\)/\1/p' "$OUT/console.log" | tail -1)
unresolved=$(grep -c 'called unresolved function' "$OUT/console.log" 2>/dev/null || echo 0)

{
	echo "map           $MAP"
	echo "mission asked ${POP:-the map default}"
	echo "mission run   ${popfile:-none}"
	echo "waves started $(grep -c 'Wave #1 initialized' "$OUT/console.log")"
	echo "server alive  $alive"
	echo "sigsegv       $(grep -c 'CExtSigsegv' "$OUT/console.log") load line(s)"
	echo "addresses     OK $ok  FAIL $fail"
	echo "mods          OK $modok  FAILED $modfail"
	echo "unresolved calls $unresolved"
} | tee "$OUT/result.txt"

for pid in $(pgrep -f 'wine srcds' || true); do kill "$pid" 2>/dev/null; done
wait "$runner" 2>/dev/null
sleep 2
