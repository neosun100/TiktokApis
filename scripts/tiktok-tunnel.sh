#!/usr/bin/env bash
# SOCKS5 tunnel for TikTok traffic (TikTok is geo-blocked in Hong Kong).
#
#   scripts/tiktok-tunnel.sh [start|status|stop|check]     (default: start)
#
# Env (all optional):
#   TIKTOK_TUNNEL_HOST   ssh alias of the exit server   (default: seattle-neo)
#   TIKTOK_TUNNEL_PORT   local SOCKS5 port              (default: 11080)
# Point the client at it with TIKTOK_PROXY=socks5h://127.0.0.1:$PORT (~/.env).
set -euo pipefail

HOST="${TIKTOK_TUNNEL_HOST:-seattle-neo}"
PORT="${TIKTOK_TUNNEL_PORT:-11080}"
# The pattern identifies exactly this tunnel's ssh process.
PATTERN="ssh .*-D 127.0.0.1:${PORT} .*${HOST}"

running() { pgrep -f "$PATTERN" >/dev/null 2>&1; }

check() {
  # 200 = reachable; a 302 to /about means the exit is in a blocked region.
  local out
  out=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" --max-time 15 \
        --socks5-hostname "127.0.0.1:${PORT}" https://www.tiktok.com/) || true
  if [[ "$out" == 200* ]]; then
    echo "ok: tiktok.com reachable via ${HOST} (127.0.0.1:${PORT})"
  else
    echo "FAIL: tiktok.com via ${HOST} -> '${out:-no response}'" >&2
    return 1
  fi
}

case "${1:-start}" in
  start)
    if running; then
      if check >/dev/null 2>&1; then
        echo "already running: 127.0.0.1:${PORT} -> ${HOST}"
        check
        exit 0
      fi
      # The process can outlive its connection (network blip; ServerAlive
      # needs 30s x 3 to notice).  A tunnel that cannot reach TikTok is dead.
      echo "running but not reachable; restarting" >&2
      pkill -f "$PATTERN" || true
      sleep 1
    fi
    ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 -f -N -D "127.0.0.1:${PORT}" "$HOST"
    echo "started: 127.0.0.1:${PORT} -> ${HOST}"
    check
    ;;
  status)
    if running; then echo "running: 127.0.0.1:${PORT} -> ${HOST}"; check; else echo "stopped"; exit 1; fi
    ;;
  check)
    check
    ;;
  stop)
    if running; then pkill -f "$PATTERN"; echo "stopped"; else echo "not running"; fi
    ;;
  *)
    echo "usage: $0 [start|status|stop|check]" >&2; exit 2
    ;;
esac
