#!/bin/sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INPUT="$ROOT_DIR/examples/input.json"
OUTPUT="$ROOT_DIR/examples/output.json"

cargo run -p clob-host --release -- --execute --input "$INPUT" --output "$OUTPUT"
echo "Wrote $OUTPUT"
