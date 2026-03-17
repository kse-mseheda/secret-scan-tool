#!/bin/bash
set -e

IMAGE_NAME="custom-secret-detect"
SCAN_PATH="${1:-.}"
BASELINE_FLAG=""

if [ -f ".secret-baseline.json" ]; then
    BASELINE_FLAG="--baseline /scan/.secret-baseline.json"
fi

echo "Building Docker image..."
docker build -q -t "$IMAGE_NAME" .

echo "Scanning ${SCAN_PATH} for secrets..."
docker run --rm \
  -v "$(pwd)":/scan \
  $BASELINE_FLAG \
  "$IMAGE_NAME" \
  "/scan/${SCAN_PATH}"
