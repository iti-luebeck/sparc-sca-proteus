#!/usr/bin/env bash
#
# run_multi_trace_tvla.sh — Multi-trace TVLA pipeline for CellIFT Proteus.
#
# Runs the per-cycle CSV logger binary for N matched scenario pairs
# (Group A and Group B), then calls multi_tvla_driver.py for Welch analysis.
#
# Each trace i:
#   Group A: sw/{PREFIX_A}_{i:03d}/build/app.elf  (key₁, random plaintextᵢ)
#   Group B: sw/{PREFIX_B}_{i:03d}/build/app.elf  (key₂, same plaintextᵢ)
#
# Usage:
#   ./run_multi_trace_tvla.sh [N] [SIMLEN] [OUTDIR] [PREFIX_A] [PREFIX_B] [EXTRA_ARGS...]
#
# Arguments:
#   N          Number of trace pairs (default: 20)
#   SIMLEN     Simulation cycles per trace (default: 30000; AES finishes ~22600)
#   OUTDIR     Output directory for CSVs and plots (default: results/multi_tvla)
#   PREFIX_A   Scenario prefix for Group A (default: multi_aes_unmasked_a)
#   PREFIX_B   Scenario prefix for Group B (default: multi_aes_unmasked_b)
#   EXTRA_ARGS Passed through to multi_tvla_driver.py (e.g. --plot --delta)
#
# Environment:
#   JOBS       Parallel trace-pair workers (default: auto CPU count; set explicitly to cap)
#   LEADTICKS  Ticks consumed before CSV loop (default: 5)
#
# Examples:
#   ./run_multi_trace_tvla.sh 20 30000 results/unmasked multi_aes_unmasked_a multi_aes_unmasked_b --plot
#   ./run_multi_trace_tvla.sh 100 30000 results/masked multi_aes_masked_a multi_aes_masked_b --plot

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

N="${1:-20}"
SIMLEN="${2:-30000}"
OUTDIR="${3:-${SCRIPT_DIR}/results/multi_tvla}"
PREFIX_A="${4:-multi_aes_unmasked_a}"
PREFIX_B="${5:-multi_aes_unmasked_b}"
shift 5 2>/dev/null || true   # remaining args passed to multi_tvla_driver.py
if [[ -n "${JOBS:-}" ]]; then
    JOBS="$JOBS"
elif command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc)"
else
    JOBS=1
fi
LEADTICKS="${LEADTICKS:-5}"

if ! [[ "$LEADTICKS" =~ ^[0-9]+$ ]]; then
    echo "ERROR: LEADTICKS must be a non-negative integer (got '${LEADTICKS}')"
    exit 1
fi

EXPECTED_ROWS=$(( SIMLEN - LEADTICKS ))
if [[ "$EXPECTED_ROWS" -le 0 ]]; then
    echo "ERROR: expected CSV rows must be positive (SIMLEN=${SIMLEN}, LEADTICKS=${LEADTICKS})"
    exit 1
fi

ENV_SH="/mnt/nvme1n1p1/cellift-meta-leakage/env.sh"
CSV_BIN="${SCRIPT_DIR}/build/run_cellift_csvlog_0.1/default-verilator/Vproteus_tiny_soc"

# ── Sanity checks ─────────────────────────────────────────────────────────────
source "$ENV_SH"

if [[ ! -x "$CSV_BIN" ]]; then
    echo "ERROR: CSV logger binary not found: $CSV_BIN"
    echo "       Build it with: fusesoc --cores-root=. run --build run_cellift_csvlog"
    exit 1
fi

if [[ "$N" -lt 2 ]]; then
    echo "ERROR: N must be at least 2 for Welch t-test (got N=${N})"
    exit 1
fi

if ! [[ "$JOBS" =~ ^[0-9]+$ ]] || [[ "$JOBS" -lt 1 ]]; then
    echo "ERROR: JOBS must be a positive integer (got '${JOBS}')"
    exit 1
fi

mkdir -p "$OUTDIR"

validate_csv() {
    local csv_path="$1"
    local expect_rows="$2"

    if [[ ! -s "$csv_path" ]]; then
        echo "  ERROR: CSV missing or empty: $csv_path"
        return 1
    fi

    python3 - "$csv_path" "$expect_rows" <<'PY'
import csv
import sys

path = sys.argv[1]
expect_rows = int(sys.argv[2])
need = ["cycle", "leakage_counter_t0", "hamming_weight_counter_t0", "hamming_distance_counter_t0"]

rows = 0
with open(path, newline="") as f:
    r = csv.DictReader(f)
    if r.fieldnames != need:
        print(f"ERROR: CSV header mismatch in {path}: {r.fieldnames}")
        sys.exit(2)
    for row in r:
        rows += 1
        vals = [int(row[k]) for k in need]
        cyc, lc, hw, hd = vals
        if cyc != rows - 1:
            print(f"ERROR: non-consecutive cycle index in {path} at row {rows}: got {cyc}")
            sys.exit(3)
        if lc < 0 or hw < 0 or hd < 0:
            print(f"ERROR: negative counter in {path} at cycle {cyc}: lc={lc} hw={hw} hd={hd}")
            sys.exit(5)

if rows != expect_rows:
    print(f"ERROR: CSV row count mismatch in {path}: got {rows}, expected {expect_rows}")
    sys.exit(6)
PY
}

# ── Helper: run one CSV simulation ────────────────────────────────────────────
run_trace() {
    local label="$1"
    local scenario="$2"
    local csv_out="$3"

    local elf="${SCRIPT_DIR}/sw/${scenario}/build/app.elf"
    local taint="${SCRIPT_DIR}/taint_data/${scenario}/taint_data.txt"

    if [[ ! -f "$elf" ]]; then
        echo "  ERROR: ELF not found: $elf"
        echo "         Run compile_scenarios.sh ${scenario%_[0-9]*} first."
        exit 1
    fi

    if [[ ! -f "$taint" ]]; then
        echo "  ERROR: taint file not found: $taint"
        exit 1
    fi

    SIMLEN="$SIMLEN" \
    TRACEFILE=/dev/null \
    CSVFILE="$csv_out" \
    SIMSRAMELF="$elf" \
    SIMSRAMTAINT="$taint" \
    "$CSV_BIN" 2>&1 | grep -v "Writing ELF word" || true
}

run_pair() {
    local idx="$1"
    local scenario_a="${PREFIX_A}_${idx}"
    local scenario_b="${PREFIX_B}_${idx}"
    local csv_a="${OUTDIR}/group_a_${idx}.csv"
    local csv_b="${OUTDIR}/group_b_${idx}.csv"

    echo "── Trace ${idx} / $(printf "%03d" $((N-1))) ───────────────────────────────────"

    if [[ -f "$csv_a" && -f "$csv_b" ]]; then
        echo "  ↩  Already exists — skipping (delete to re-run)"
        return 0
    fi

    echo "  [A] ${scenario_a}"
    run_trace "A" "$scenario_a" "$csv_a"
    validate_csv "$csv_a" "$EXPECTED_ROWS"
    echo "      → ${csv_a}"

    echo "  [B] ${scenario_b}"
    run_trace "B" "$scenario_b" "$csv_b"
    validate_csv "$csv_b" "$EXPECTED_ROWS"
    echo "      → ${csv_b}"
    echo ""
}

# ── Main loop ─────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════════════════════"
echo "  CellIFT Multi-Trace TVLA  —  N=${N}  SIMLEN=${SIMLEN}"
echo "  Group A prefix : ${PREFIX_A}"
echo "  Group B prefix : ${PREFIX_B}"
echo "  Output dir     : ${OUTDIR}"
echo "  Parallel jobs  : ${JOBS}"
echo "  Row expectation: SIMLEN-LEADTICKS = ${SIMLEN}-${LEADTICKS} = ${EXPECTED_ROWS}"
echo "════════════════════════════════════════════════════════════"
echo ""

t_start=$(date +%s)

if [[ "$JOBS" -eq 1 ]]; then
    for i in $(seq 0 $((N - 1))); do
        idx=$(printf "%03d" "$i")
        run_pair "$idx"

        elapsed=$(( $(date +%s) - t_start ))
        done_count=$((i + 1))
        if [[ $done_count -gt 0 && $elapsed -gt 0 ]]; then
            remaining=$(( (N - done_count) * elapsed / done_count ))
            echo "  ⏱  ${done_count}/${N} done  (~${remaining}s remaining)"
            echo ""
        fi
    done
else
    pids=()
    for i in $(seq 0 $((N - 1))); do
        idx=$(printf "%03d" "$i")
        while [[ $(jobs -rp | wc -l) -ge "$JOBS" ]]; do
            sleep 0.5
        done
        run_pair "$idx" &
        pids+=("$!")
    done

    fail=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            fail=1
        fi
    done
    if [[ "$fail" -ne 0 ]]; then
        echo "ERROR: one or more parallel trace workers failed"
        exit 1
    fi
fi

t_end=$(date +%s)
echo "════════════════════════════════════════════════════════════"
echo "  All ${N} trace pairs completed in $(( t_end - t_start ))s"
echo "  Running Welch TVLA analysis..."
echo "════════════════════════════════════════════════════════════"
echo ""

python3 "${SCRIPT_DIR}/multi_tvla_driver.py" \
    "$OUTDIR" \
    --threshold 4.5 \
    --out "${OUTDIR}/welch" \
    "$@"

echo ""
echo "Done. Results in: ${OUTDIR}/"
echo "  CSVs         : ${OUTDIR}/group_a_*.csv  group_b_*.csv"
echo "  Analysis plot: ${OUTDIR}/welch_mean.png  (and/or welch_welch.png, driver-dependent)"
echo "  Summary      : ${OUTDIR}/welch_summary.txt"
