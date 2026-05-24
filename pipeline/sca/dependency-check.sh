#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/pipeline/sca/reports"
PROJECT_NAME="lab09-vulnerable-app"
DATA_DIR="${HOME}/.dependency-check-data"

mkdir -p "${OUT_DIR}" "${DATA_DIR}"

echo "============================================================"
echo " OWASP Dependency-Check SCA — lab09"
echo "============================================================"

if command -v dependency-check >/dev/null 2>&1; then
  DC_CMD="dependency-check"
elif [ -x "${ROOT_DIR}/pipeline/sca/dependency-check/bin/dependency-check.sh" ]; then
  DC_CMD="${ROOT_DIR}/pipeline/sca/dependency-check/bin/dependency-check.sh"
else
  echo "[!] ERROR: 'dependency-check' CLI не найден."
  echo "    Установите: https://owasp.org/www-project-dependency-check/"
  exit 1
fi

if [ "${1:-}" = "--update" ]; then
  echo "[*] Обновление базы NVD в ${DATA_DIR}..."
  "${DC_CMD}" --updateonly --data "${DATA_DIR}" \
    ${NVD_API_KEY:+--nvdApiKey "$NVD_API_KEY"}
  echo "[+] NVD-данные обновлены."
  exit 0
fi

echo "[*] Скан requirements.txt с кэшем NVD (${DATA_DIR})"

"${DC_CMD}" \
  --scan "${ROOT_DIR}/app/requirements.txt" \
  --format HTML --format JSON \
  --project "${PROJECT_NAME}" \
  --out "${OUT_DIR}" \
  --data "${DATA_DIR}" \
  --noupdate \
  --enableExperimental \
  --failOnCVSS 9 \
  --log "${OUT_DIR}/dependency-check.log" || EXIT_CODE=$?

EXIT_CODE=${EXIT_CODE:-0}
echo ""
echo "[+] Отчёты в: ${OUT_DIR}"
exit "${EXIT_CODE}"
