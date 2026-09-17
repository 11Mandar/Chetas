#!/usr/bin/env bash
# ==============================================================================
# Chetas ULPF — Linux Telemetry Shipper Launcher
# Double-click or run: ./Stream-Linux-Logs.sh [Chetas_IP]
# ==============================================================================

DEFAULT_IP="10.180.250.129"
TARGET_IP="${1:-$DEFAULT_IP}"

# If no argument passed, give 5 seconds to enter custom IP or press Enter
if [ -z "$1" ]; then
  read -t 5 -p "Enter Chetas Server IP (Press Enter for ${DEFAULT_IP}): " INPUT_IP
  [ -n "$INPUT_IP" ] && TARGET_IP="$INPUT_IP"
fi

echo ""
echo "Starting Chetas Linux Log Streamer to http://${TARGET_IP}:3000..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/scripts/stream_linux_logs.sh" ]; then
  bash "${SCRIPT_DIR}/scripts/stream_linux_logs.sh" "${TARGET_IP}" 3000
else
  # Inline fallback streamer
  LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  [ -z "$LOCAL_IP" ] && LOCAL_IP="127.0.0.1"
  HOSTNAME=$(hostname)

  echo "Streaming from ${HOSTNAME} (${LOCAL_IP}) -> ${TARGET_IP}..."

  (journalctl -n 25 --no-pager 2>/dev/null || dmesg | tail -n 25) | while IFS= read -r line; do
    [ -z "$line" ] && continue
    CLEAN_MSG=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g')
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    curl -s -X POST "http://${TARGET_IP}:3000/api/logs/ingest" \
      -H "Content-Type: text/plain" \
      -H "x-source-id: src-linux-${HOSTNAME}" \
      -d "{
        \"source_ip\": \"${LOCAL_IP}\",
        \"destination_ip\": \"${TARGET_IP}\",
        \"source_host\": \"${HOSTNAME}\",
        \"vendor\": \"Ubuntu Linux\",
        \"product\": \"Remote-Linux-${HOSTNAME}\",
        \"timestamp\": \"${TIMESTAMP}\",
        \"message\": \"${CLEAN_MSG}\"
      }" > /dev/null

    echo "[Ingested] ${LOCAL_IP} -> ${TARGET_IP} | ${line:0:65}..."
    sleep 0.1
  done
fi
