#!/bin/bash
# Minimal idle-cover X session for users that successfully log into xrdp
# (i.e. probers and any operator using this as a real RDP server).
#
# We render a black-ish desktop with a ticking clock so screen updates
# happen at a believable cadence. The point is that a probing session,
# if it gets past auth, sees something that looks like a normal
# locked-down corporate desktop.

# Start openbox WM in the background.
openbox &

# A clock with seconds — produces one screen update per second, matching
# what a real RDP session would push.
xclock -update 1 -geometry 200x200-10-10 &

# Idle xterm so the desktop isn't empty. -fa 0 -fb 0 suppress fontserver hits.
xterm -fullscreen -bg black -fg gray30 -T jumpbox &

# Block forever so xrdp keeps the session open.
wait
