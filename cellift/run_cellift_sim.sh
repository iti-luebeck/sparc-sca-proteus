#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIMLEN="${1:-30000}"
TRACEFILE="${2:-/dev/null}"
SCENARIO="${3:-scenario_aes128_masked_key}"

: "${SPARC_SCA_ROOT:=$(cd "${SCRIPT_DIR}/../../.." && pwd)}"
ENV_SH="${SPARC_SCA_ROOT}/env.sh"
SIM_BIN="${SCRIPT_DIR}/build/run_cellift_fasttrace_0.1/default-verilator/Vproteus_tiny_soc"
ELF="${SCRIPT_DIR}/sw/${SCENARIO}/build/app.elf"
TAINT="${SCRIPT_DIR}/taint_data/${SCENARIO}/taint_data.txt"

if [[ "${CELLIFT_ENV_SOURCED:-}" != "yes" ]]; then
    source "$ENV_SH"
fi

echo "=== CellIFT Proteus Simulation ==="
echo "SCENARIO:  $SCENARIO"
echo "SIMLEN:    $SIMLEN"
echo "TRACEFILE: $TRACEFILE"
echo "ELF:       $ELF"
echo "TAINT:     $TAINT"
echo ""

SIMLEN="$SIMLEN" TRACEFILE="$TRACEFILE" SIMSRAMELF="$ELF" SIMSRAMTAINT="$TAINT" "$SIM_BIN"
