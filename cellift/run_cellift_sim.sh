#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIMLEN="${1:-30000}"
TRACEFILE="${2:-/dev/null}"
SCENARIO="${3:-scenario_aes128_masked_key}"

ENV_SH="/mnt/nvme1n1p1/cellift-meta-leakage/env.sh"
SIM_BIN="${SCRIPT_DIR}/build/run_cellift_fasttrace_0.1/default-verilator/Vproteus_tiny_soc"
ELF="${SCRIPT_DIR}/sw/${SCENARIO}/build/app.elf"
TAINT="${SCRIPT_DIR}/taint_data/${SCENARIO}/taint_data.txt"

source "$ENV_SH"

echo "=== CellIFT Proteus Simulation ==="
echo "SCENARIO:  $SCENARIO"
echo "SIMLEN:    $SIMLEN"
echo "TRACEFILE: $TRACEFILE"
echo "ELF:       $ELF"
echo "TAINT:     $TAINT"
echo ""

SIMLEN="$SIMLEN" TRACEFILE="$TRACEFILE" SIMSRAMELF="$ELF" SIMSRAMTAINT="$TAINT" "$SIM_BIN"
