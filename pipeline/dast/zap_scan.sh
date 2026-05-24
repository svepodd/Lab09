#!/usr/bin/env bash

set -euo pipefail

ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
TARGET_URL="${TARGET_URL:-http://host.docker.internal:8080}"
OUT_DIR="pipeline/dast/reports"

mkdir -p "$OUT_DIR"
cp pipeline/dast/zap-baseline.conf "$OUT_DIR/zap-baseline.conf"

echo "============================================================"
echo " OWASP ZAP baseline scan — lab09"
echo "============================================================"
echo "[i] Target: ${TARGET_URL}"

docker run --rm \
  -v "$(pwd)/$OUT_DIR":/zap/wrk \
  "$ZAP_IMAGE" \
  zap-baseline.py \
  -t "$TARGET_URL" \
  -c /zap/wrk/zap-baseline.conf \
  -J /zap/wrk/zap-report.json \
  -r /zap/wrk/zap-report.html \
  -I

echo ""
echo "[+] DAST reports saved to $OUT_DIR"
ls -lh "$OUT_DIR"/zap-report.* 2>/dev/null || echo "[!] Отчёты не найдены"
