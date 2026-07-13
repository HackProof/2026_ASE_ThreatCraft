#!/usr/bin/env bash

set -Eeuo pipefail

export DISPLAY="${DISPLAY:-:99}"
export SCREEN_GEOMETRY="${SCREEN_GEOMETRY:-1600x1000x24}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/runtime-threatcraft}"

mkdir -p \
    "${XDG_RUNTIME_DIR}" \
    /workspace \
    /app/code/frontend/out

chmod 700 "${XDG_RUNTIME_DIR}"

echo "[ThreatCraft] Starting virtual display: ${DISPLAY}"

Xvfb "${DISPLAY}" \
    -screen 0 "${SCREEN_GEOMETRY}" \
    -ac \
    -nolisten tcp \
    +extension GLX \
    +render \
    -noreset \
    >/tmp/xvfb.log 2>&1 &

# X 서버가 실제로 준비될 때까지 대기
for _ in $(seq 1 50); do
    if xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

if ! xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
    echo "[ThreatCraft] Xvfb failed to start." >&2
    cat /tmp/xvfb.log >&2 || true
    exit 1
fi

echo "[ThreatCraft] Starting Openbox"

openbox-session \
    >/tmp/openbox.log 2>&1 &

echo "[ThreatCraft] Starting VNC server"

x11vnc \
    -display "${DISPLAY}" \
    -rfbport 5900 \
    -listen 127.0.0.1 \
    -forever \
    -shared \
    -nopw \
    -noxdamage \
    >/tmp/x11vnc.log 2>&1 &

echo "[ThreatCraft] Starting noVNC on port 6080"

websockify \
    --web=/usr/share/novnc \
    0.0.0.0:6080 \
    127.0.0.1:5900 \
    >/tmp/novnc.log 2>&1 &

cd /app/code/frontend

echo "[ThreatCraft] Launching GUI"

exec python tool_attack_paths.py
