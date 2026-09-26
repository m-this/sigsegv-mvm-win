#!/bin/bash
# Which class owns the vtables the CTFBotPushToCapturePoint constructor
# candidate (0x5883f0) writes: 0x1089d1d8 and 0x1089d348.
grep -l -i "1089d1d8\|1089d348" derived/win-vtables/* | head
