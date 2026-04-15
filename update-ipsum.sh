#!/usr/bin/env bash
# Refresh local ipsum.txt from the official stamparm feed.
#
# Usage:
#   ./update-ipsum.sh
#   ./update-ipsum.sh /path/to/ipsum.txt

set -euo pipefail

SOURCE_URL="${IPSUM_SOURCE_URL:-https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_FILE="${1:-${SCRIPT_DIR}/ipsum.txt}"
DEST_DIR="$(dirname "${DEST_FILE}")"

if ! command -v curl >/dev/null 2>&1; then
    echo "[!] curl is required"
    exit 1
fi

mkdir -p "${DEST_DIR}"
TMP_FILE="$(mktemp "${DEST_DIR}/.ipsum.tmp.XXXXXX")"
trap 'rm -f "${TMP_FILE}"' EXIT

curl -fsSL \
    --retry 3 \
    --retry-delay 2 \
    --connect-timeout 15 \
    --max-time 120 \
    "${SOURCE_URL}" \
    -o "${TMP_FILE}"

# Basic safety check so an HTML/error page never replaces the feed.
if ! grep -Eq '^[0-9A-Fa-f:.\/]+[[:space:]]+[0-9]+$' "${TMP_FILE}"; then
    echo "[!] Downloaded content does not look like an IPsum feed; aborting"
    exit 1
fi

if [[ -f "${DEST_FILE}" ]] && cmp -s "${TMP_FILE}" "${DEST_FILE}"; then
    echo "[+] ipsum.txt is already up to date"
    exit 0
fi

mv -f "${TMP_FILE}" "${DEST_FILE}"

indicator_count="$(grep -Evc '^[[:space:]]*#|^[[:space:]]*$' "${DEST_FILE}")"
echo "[+] Updated ${DEST_FILE} from ${SOURCE_URL} (${indicator_count} indicators)"
