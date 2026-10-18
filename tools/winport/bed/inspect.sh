#!/bin/bash
mkdir -p derived/bins
cp winbins/tf/bin/server.dll derived/bins/server-prev.dll
cp game-windows/tf/bin/server.dll derived/bins/server-new.dll
cp game-linux/tf/bin/server_srv.so derived/bins/server_srv-new.so
ls -la derived/bins
