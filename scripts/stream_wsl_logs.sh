#!/usr/bin/env bash
# ==============================================================================
# Chetas ULPF — Real-time WSL2 Linux Log Shipper
# Streams authentic Linux logs from WSL directly to Windows Chetas Command Center
# ==============================================================================

# In WSL2, the Windows Host IP is always available via default gateway:
WINDOWS_HOST=$(ip route show default 2>/dev/null | awk '{print $3}')
[ -z "$WINDOWS_HOST" ] && WINDOWS_HOST="172.26.32.1"
CHETAS_PORT="3000"
CHETAS_URL="http://${WINDOWS_HOST}:${CHETAS_PORT}"

# Local WSL IP
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$LOCAL_IP" ] && LOCAL_IP="172.26.47.75"

HOSTNAME=$(hostname)

echo "================================================================"
echo " Chetas ULPF — Real-time WSL Linux Log Streamer"
echo " WSL Host:     ${HOSTNAME} (Ubuntu Linux)"
echo " Source IP:    ${LOCAL_IP}"
echo " Chetas Host:  ${WINDOWS_HOST}:${CHETAS_PORT}"
echo " Endpoint:     ${CHETAS_URL}/api/logs/ingest"
echo "================================================================"

# Check connectivity
echo -n "Checking connectivity to Chetas... "
if curl -s -m 2 "${CHETAS_URL}/api/status" > /dev/null; then
  echo "CONNECTED! OK"
else
  echo "FAILED. Ensure Chetas is running on Windows."
  exit 1
fi

echo ""
echo "Streaming authentic Linux logs to Chetas..."
echo "----------------------------------------------------------------"

# Stream last 20 events immediately, then follow new events
(journalctl -n 20 --no-pager 2>/dev/null || dmesg | tail -n 20) | while IFS= read -r line; do
  [ -z "$line" ] && continue

  CLEAN_MSG=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g')
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  PAYLOAD=$(cat <<EOF
{
  "source_ip": "${LOCAL_IP}",
  "destination_ip": "${WINDOWS_HOST}",
  "source_host": "${HOSTNAME}",
  "vendor": "Ubuntu Linux (WSL)",
  "product": "WSL2-Linux-${HOSTNAME}",
  "level": "Information",
  "timestamp": "${TIMESTAMP}",
  "message": "${CLEAN_MSG}"
}
EOF
)

  curl -s -X POST "${CHETAS_URL}/api/logs/ingest" \
    -H "Content-Type: text/plain" \
    -H "x-source-id: src-wsl-${HOSTNAME}" \
    -d "$PAYLOAD" > /dev/null

  echo "[Ingested] ${LOCAL_IP} -> ${WINDOWS_HOST} | ${line:0:65}..."
  sleep 0.1
done

echo "----------------------------------------------------------------"
echo "All logs delivered to Chetas successfully!"
echo "View them live at http://localhost:3000/#logs"
