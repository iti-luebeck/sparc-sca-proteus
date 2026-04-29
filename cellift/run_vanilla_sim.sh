#!/usr/bin/env bash
# Run the Proteus vanilla simulator with VCD trace output.
#
# Usage:
#   ./run_vanilla_sim.sh [SIMLEN] [TRACEFILE] [SCENARIO]
#
# Defaults:
#   SIMLEN     = 50000   (cycles; AES completes around cycle 22,600)
#   TRACEFILE  = traces/vanilla_aes.vcd
#   SCENARIO   = scenario_aes128_masked_key

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Arguments / defaults ──────────────────────────────────────────────────────
SIMLEN="${1:-50000}"
TRACEFILE="${2:-${SCRIPT_DIR}/traces/vanilla_aes.vcd}"
SCENARIO="${3:-scenario_aes128_masked_key}"

# ── Paths ─────────────────────────────────────────────────────────────────────
: "${SPARC_SCA_ROOT:=$(cd "${SCRIPT_DIR}/../../.." && pwd)}"
ENV_SH="${SPARC_SCA_ROOT}/env.sh"
SIM_BIN="${SCRIPT_DIR}/build/run_vanilla_trace_0.1/default-verilator/Vproteus_tiny_soc"
ELF="${SCRIPT_DIR}/sw/${SCENARIO}/build/app.elf"

# ── Sanity checks ────────────────────────────────────────────────────────────────────────────────
for f in "$SIM_BIN" "$ELF"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: required file not found: $f" >&2
        exit 1
    fi
done

mkdir -p "$(dirname "$TRACEFILE")"

# ── Source CellIFT environment ────────────────────────────────────────────────────────
if [[ "${CELLIFT_ENV_SOURCED:-}" != "yes" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_SH"
fi

# ── Run ───────────────────────────────────────────────────────────────────────
echo "=== Proteus Vanilla Simulator ==="
echo "  SIMLEN    : ${SIMLEN} cycles"
echo "  ELF       : ${ELF}"
echo "  TRACEFILE : ${TRACEFILE}"
echo ""

SIMLEN="$SIMLEN" \
TRACEFILE="$TRACEFILE" \
SIMSRAMELF="$ELF" \
    "$SIM_BIN"

SIM_EXIT=$?

echo ""
if [[ $SIM_EXIT -eq 0 ]]; then
    echo "Simulation exited cleanly (exit 0)."
else
    echo "Simulation exited with code ${SIM_EXIT}." >&2
fi

if [[ -f "$TRACEFILE" ]]; then
    SIZE=$(du -sh "$TRACEFILE" | cut -f1)
    echo "VCD written: ${TRACEFILE}  (${SIZE})"
fi
