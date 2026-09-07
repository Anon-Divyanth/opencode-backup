#!/usr/bin/env bash
# Persistent CDP bridge watchdog: keeps the bridge to the live Chrome profile
# running on 127.0.0.1:9222. Restarts it if it crashes. Run detached.
set -u
NODE_BIN="$HOME/.config/nvm/versions/node/v24.18.0/bin/node"
BRIDGE="$HOME/.config/opencode/browser/cdp-bridge.js"
LOG="$HOME/.config/opencode/browser/cdp-bridge.log"
while true; do
  "$NODE_BIN" "$BRIDGE" >>"$LOG" 2>&1
  echo "[watchdog] bridge exited ($(date)), restarting in 2s" >>"$LOG"
  sleep 2
done
