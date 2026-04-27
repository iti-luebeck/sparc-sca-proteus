#!/usr/bin/env bash
#
# run_signal_correlation.sh — RTL signal and instruction root-cause analysis.
#
# For a given pair of CellIFT scenarios and a set of leakage cycles, this
# script runs three analysis passes:
#
#   Step 1  CellIFT fasttrace VCDs for both scenarios (short, covers the
#           leakage window only — 100–300 cycles is usually enough).
#
#   Step 2  leakage_signals.py — compares the two VCDs signal-by-signal and
#           ranks RTL signals by key-dependent Hamming weight at each target
#           cycle.  Produces heatmap and timeline PNG plots.
#
#   Step 3  Vanilla VCD (no taint overhead) for the Group A scenario.
#           Required by pc_at_leakage.py for clean pipeline signal names.
#
#   Step 4  pc_at_leakage.py — maps each leakage cycle to the fetch PC,
#           retire PC, and source line via addr2line.
#
# Usage:
#   ./run_signal_correlation.sh [SCENARIO_A] [SCENARIO_B] [CYCLES] [SIMLEN] [OUT_PREFIX]
#
# Arguments:
#   SCENARIO_A   Group A scenario name (default: scenario_aes128_unmasked_key1)
#   SCENARIO_B   Group B scenario name (default: scenario_aes128_unmasked_key2)
#   CYCLES       Space-separated list of CSV cycles to analyse (default: "36 37 38 39 40")
#   SIMLEN       Simulation cycles — must exceed max(CYCLES) (default: 200)
#   OUT_PREFIX   Output file prefix for plots (default: signal_out)
#
# Examples:
#   # Unmasked AES — known leakage at cycle 37
#   ./run_signal_correlation.sh \
#       scenario_aes128_unmasked_key1 \
#       scenario_aes128_unmasked_key2 \
#       "36 37 38 39 40" 200 results/unmasked_signals
#
#   # Masked AES — substitute first leaky cycle from TVLA output
#   ./run_signal_correlation.sh \
#       scenario_aes128_masked_key1 \
#       scenario_aes128_masked_key2 \
#       "44 45 46 47 48" 300 results/masked_signals

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCENARIO_A="${1:-scenario_aes128_unmasked_key1}"
SCENARIO_B="${2:-scenario_aes128_unmasked_key2}"
CYCLES="${3:-36 37 38 39 40}"
SIMLEN="${4:-200}"
OUT_PREFIX="${5:-signal_out}"
SIGNAL_JSON="${OUT_PREFIX}_signals.json"
INSTR_JSON="${OUT_PREFIX}_instructions.json"
DATA_SIGNAL_JSON="${OUT_PREFIX}_data_signals.json"

ENV_SH="/mnt/nvme1n1p1/cellift-meta-leakage/env.sh"
FAST_BIN="${SCRIPT_DIR}/build/run_cellift_fasttrace_0.1/default-verilator/Vproteus_tiny_soc"
FAST_BIN_FST="${SCRIPT_DIR}/build/run_cellift_fasttrace_fst_0.1/default-verilator/Vproteus_tiny_soc"
VANILLA_BIN="${SCRIPT_DIR}/build/run_vanilla_trace_0.1/default-verilator/Vproteus_tiny_soc"
VANILLA_BIN_FST="${SCRIPT_DIR}/build/run_vanilla_trace_fst_0.1/default-verilator/Vproteus_tiny_soc"
# VCD writer in Verilator has a ~4GB internal file-offset limit (32-bit counter).
# Above this threshold we use the FST binary + fst2vcd to avoid SIGABRT.
# Applied to both fasttrace and vanilla simulations.
FST_SIMLEN_THRESHOLD=300000

ELF_A="${SCRIPT_DIR}/sw/${SCENARIO_A}/build/app.elf"
ELF_B="${SCRIPT_DIR}/sw/${SCENARIO_B}/build/app.elf"
TAINT_A="${SCRIPT_DIR}/taint_data/${SCENARIO_A}/taint_data.txt"
TAINT_B="${SCRIPT_DIR}/taint_data/${SCENARIO_B}/taint_data.txt"

OUT_DIR="$(dirname "$OUT_PREFIX")"
TMP_ROOT="${OUT_DIR}/.tmp_signal_corr_$$"
VCD_A="${TMP_ROOT}/cellift_sig_a.vcd"
VCD_B="${TMP_ROOT}/cellift_sig_b.vcd"
SIM_LOG_A="${TMP_ROOT}/fasttrace_a.log"
SIM_LOG_B="${TMP_ROOT}/fasttrace_b.log"
SIM_LOG_VAN="${TMP_ROOT}/vanilla.log"
mkdir -p "$TMP_ROOT"
mkdir -p "${SCRIPT_DIR}/traces"
VCD_VAN="${SCRIPT_DIR}/traces/vanilla_${SCENARIO_A}.vcd"
VCD_VAN_B="${SCRIPT_DIR}/traces/vanilla_${SCENARIO_B}.vcd"

SIM_STDOUT_MODE="${SIM_STDOUT_MODE:-quiet}"   # quiet | summary | raw
# Timeout scales with SIMLEN: SIMLEN/300 seconds, minimum 600 s.
_computed_timeout=$(( SIMLEN / 300 ))
if [[ "$_computed_timeout" -lt 600 ]]; then _computed_timeout=600; fi
SIM_CORR_TIMEOUT="${SIM_CORR_TIMEOUT:-${_computed_timeout}}"

run_with_stdout_mode() {
    local log_file="$1"
    shift

    if [[ "$SIM_STDOUT_MODE" == "raw" ]]; then
        timeout "$SIM_CORR_TIMEOUT" "$@" >"$log_file" 2>&1
    elif [[ "$SIM_STDOUT_MODE" == "summary" ]]; then
        timeout "$SIM_CORR_TIMEOUT" "$@" 2>&1 | awk '/SIMLEN set|Preloading boot rom ELF|WARNING: no software halt|Testbench with traces complete|Elapsed time/' >"$log_file"
    else
        timeout "$SIM_CORR_TIMEOUT" "$@" 2>&1 \
            | awk '/SIMLEN set|Preloading boot rom ELF|WARNING: no software halt|Testbench|Elapsed time|fstMmap|Error|error|Bus error|Aborted/' \
            >"$log_file"
    fi
}

print_sim_log_summary() {
    local log_file="$1"
    local tag="$2"
    if [[ ! -s "$log_file" ]]; then
        return
    fi
    echo "  [${tag}] simulator log: ${log_file}"
    if [[ "$SIM_STDOUT_MODE" == "raw" ]]; then
        sed -n '1,200p' "$log_file"
        return
    fi
    rg -n "SIMLEN set|Preloading boot rom ELF|WARNING: no software halt|Testbench with traces complete|Elapsed time" "$log_file" | tail -20 || true
}

max_cycle_in_list() {
    local max=-1
    local c
    for c in "$@"; do
        [[ -z "$c" ]] && continue
        if [[ "$c" =~ ^-?[0-9]+$ ]] && (( c > max )); then
            max=$c
        fi
    done
    echo "$max"
}

vcd_last_cycle() {
    local vcd_file="$1"
    local tick_base=7
    local tick_period=5
    local last_t

    if [[ ! -f "$vcd_file" ]]; then
        echo "-1"
        return
    fi

    # Parse the last VCD timestamp and convert it to simulation cycle.
    last_t="$(awk '/^#[0-9]+$/ { t = substr($0, 2) } END { if (t == "") print "-1"; else print t }' "$vcd_file")"
    if [[ ! "$last_t" =~ ^[0-9]+$ ]]; then
        echo "-1"
        return
    fi

    echo $(( last_t / tick_period - tick_base ))
}

# KEEP_LOCAL_TMP=1 keeps tmp VCDs for debugging.
cleanup() {
    if [[ "${KEEP_LOCAL_TMP:-0}" != "1" ]]; then
        rm -rf "$TMP_ROOT"
    fi
}
trap cleanup EXIT

# ── Sanity checks ─────────────────────────────────────────────────────────────
source "$ENV_SH"

# Decide FST vs VCD mode based on SIMLEN (applied to both fasttrace and vanilla).
USE_FST=0
if [[ "$SIMLEN" -gt "$FST_SIMLEN_THRESHOLD" ]]; then
    if [[ -x "$FAST_BIN_FST" ]]; then
        USE_FST=1
    else
        echo "WARNING: SIMLEN=${SIMLEN} exceeds FST threshold=${FST_SIMLEN_THRESHOLD} but FST binary not found."
        echo "         Run: cd ${SCRIPT_DIR} && source ${ENV_SH} && fusesoc library add run_cellift_fasttrace_fst . && fusesoc --cores-root=. run --build run_cellift_fasttrace_fst"
    fi
fi

USE_VANILLA_FST=0
if [[ "$SIMLEN" -gt "$FST_SIMLEN_THRESHOLD" ]]; then
    if [[ -x "$VANILLA_BIN_FST" ]]; then
        USE_VANILLA_FST=1
    else
        echo "WARNING: SIMLEN=${SIMLEN} exceeds FST threshold=${FST_SIMLEN_THRESHOLD} but vanilla FST binary not found."
        echo "         Run: cd ${SCRIPT_DIR} && source ${ENV_SH} && fusesoc library add run_vanilla_trace_fst . && fusesoc --cores-root=. run --build run_vanilla_trace_fst"
        echo "         Falling back to VCD vanilla — may SIGABRT on large traces."
    fi
fi

_active_fast_bin="$FAST_BIN"
if [[ "$USE_FST" -eq 1 ]]; then
    _active_fast_bin="$FAST_BIN_FST"
fi
_active_vanilla_bin="$VANILLA_BIN"
if [[ "$USE_VANILLA_FST" -eq 1 ]]; then
    _active_vanilla_bin="$VANILLA_BIN_FST"
fi

for bin in "$_active_fast_bin" "$_active_vanilla_bin"; do
    if [[ ! -x "$bin" ]]; then
        echo "ERROR: binary not found: $bin"
        echo "       Build all targets with fusesoc first (see IBEX_TVLA_EVALUATION.md)"
        exit 1
    fi
done

for elf in "$ELF_A" "$ELF_B"; do
    if [[ ! -f "$elf" ]]; then
        echo "ERROR: ELF not found: $elf"
        echo "       Run: make -C sw/${SCENARIO_A}  (or compile_scenarios.sh)"
        exit 1
    fi
done

echo "════════════════════════════════════════════════════════════"
echo "  CellIFT Signal + Instruction Correlation"
echo "  Scenario A : ${SCENARIO_A}"
echo "  Scenario B : ${SCENARIO_B}"
echo "  Cycles     : ${CYCLES}"
echo "  SIMLEN     : ${SIMLEN}"
echo "  Output     : ${OUT_PREFIX}_*"
echo "════════════════════════════════════════════════════════════"
echo ""

# ── Step 1: CellIFT fasttrace VCDs ───────────────────────────────────────────
echo "── Step 1: CellIFT fasttrace VCDs (SIMLEN=${SIMLEN}, FST=${USE_FST}) ────────"
FST_TMPDIR="${FST_TMPDIR:-/mnt/nvme1n1p1/tmp}"
mkdir -p "$FST_TMPDIR"

_run_fasttrace() {
    local scenario="$1" elf="$2" taint="$3" out_vcd="$4" sim_log="$5" label="$6"
    if [[ "$USE_FST" -eq 1 ]]; then
        local fst_tmp="${out_vcd%.vcd}.fst"
        if ! run_with_stdout_mode "$sim_log" \
            env TMPDIR="${FST_TMPDIR:-/mnt/nvme1n1p1/tmp}" \
            SIMLEN="$SIMLEN" TRACEFILE="$fst_tmp" \
            SIMROMELF="$elf" SIMSRAMELF="$elf" SIMSRAMTAINT="$taint" \
            "$FAST_BIN_FST"
        then
            echo "ERROR: fasttrace simulation failed for scenario ${label}"
            echo "  log: $sim_log"
            [[ -s "$sim_log" ]] && tail -40 "$sim_log"
            return 1
        fi
        echo "  [${label}] Converting FST → VCD ..."
        if ! fst2vcd "$fst_tmp" > "$out_vcd"; then
            echo "ERROR: fst2vcd failed for scenario ${label} (FST: ${fst_tmp})"
            return 1
        fi
        rm -f "$fst_tmp"  # reclaim ~14 GB before next simulation
    else
        if ! run_with_stdout_mode "$sim_log" \
            env SIMLEN="$SIMLEN" TRACEFILE="$out_vcd" \
            SIMROMELF="$elf" SIMSRAMELF="$elf" SIMSRAMTAINT="$taint" \
            "$FAST_BIN"
        then
            echo "ERROR: fasttrace simulation failed for scenario ${label}"
            echo "  log: $sim_log"
            [[ -s "$sim_log" ]] && tail -40 "$sim_log"
            return 1
        fi
    fi
}

echo "  [A] Running ${SCENARIO_A} ..."
_run_fasttrace "$SCENARIO_A" "$ELF_A" "$TAINT_A" "$VCD_A" "$SIM_LOG_A" "A" || exit 1

echo "  [B] Running ${SCENARIO_B} ..."
_run_fasttrace "$SCENARIO_B" "$ELF_B" "$TAINT_B" "$VCD_B" "$SIM_LOG_B" "B" || exit 1

if [[ "$SIM_STDOUT_MODE" != "quiet" ]]; then
    print_sim_log_summary "$SIM_LOG_A" "A"
    print_sim_log_summary "$SIM_LOG_B" "B"
fi

echo "  [A] → ${VCD_A}  ($(du -sh "$VCD_A" 2>/dev/null | cut -f1) on disk)"
echo "  [B] → ${VCD_B}  ($(du -sh "$VCD_B" 2>/dev/null | cut -f1) on disk)"

echo ""

# ── Step 2: Signal-level leakage identification ────────────────────────────────
echo "── Step 2: Signal-level leakage (leakage_signals.py) ────────"
python3 "${SCRIPT_DIR}/leakage_signals.py" \
    "$VCD_A" "$VCD_B" \
    --cycles $CYCLES \
    --top 20 \
    --plot \
    --out "$OUT_PREFIX" \
    --out-json "$SIGNAL_JSON"

echo ""

# ── Step 3: Vanilla VCD for instruction correlation ───────────────────────────
echo "── Step 3: Vanilla VCD (instruction correlation) ────────────"
read -r -a cycle_arr <<< "$CYCLES"
REQ_MAX_CYCLE="$(max_cycle_in_list "${cycle_arr[@]}")"
REGEN_VANILLA=0

if [[ -f "$VCD_VAN" ]]; then
    VCD_LAST_CYCLE="$(vcd_last_cycle "$VCD_VAN")"
    if [[ "$VCD_LAST_CYCLE" =~ ^-?[0-9]+$ ]] && (( VCD_LAST_CYCLE >= REQ_MAX_CYCLE )); then
        echo "  ↩  Vanilla VCD already exists and covers requested cycles: ${VCD_VAN}"
        echo "     Coverage: up to cycle ${VCD_LAST_CYCLE}; requested max cycle ${REQ_MAX_CYCLE}."
    else
        echo "  ↻  Existing vanilla VCD is too short (max cycle ${VCD_LAST_CYCLE}; need ${REQ_MAX_CYCLE})."
        echo "     Regenerating: ${VCD_VAN}"
        REGEN_VANILLA=1
    fi
else
    REGEN_VANILLA=1
fi

if [[ "$REGEN_VANILLA" -eq 1 ]]; then
    echo "  Running vanilla simulation (no taint, FST=${USE_VANILLA_FST})..."
    rm -f "$VCD_VAN"
    if [[ "$USE_VANILLA_FST" -eq 1 ]]; then
        local_fst_tmp="${VCD_VAN%.vcd}.fst"
        if ! run_with_stdout_mode "$SIM_LOG_VAN" \
            env TMPDIR="${FST_TMPDIR:-/mnt/nvme1n1p1/tmp}" \
            SIMLEN="$SIMLEN" TRACEFILE="$local_fst_tmp" \
            SIMSRAMELF="$ELF_A" \
            "$_active_vanilla_bin"
        then
            echo "WARNING: vanilla simulation (A) exited non-zero — FST may be incomplete."
            [[ -s "$SIM_LOG_VAN" ]] && tail -20 "$SIM_LOG_VAN"
        fi
        if [[ ! -s "$local_fst_tmp" ]]; then
            echo "ERROR: FST output missing or empty: ${local_fst_tmp}"
            rm -f "$local_fst_tmp" "${local_fst_tmp}.hier"
            exit 1
        fi
        echo "  Converting FST → VCD ..."
        if ! fst2vcd "$local_fst_tmp" > "$VCD_VAN"; then
            echo "ERROR: fst2vcd failed for vanilla scenario A (FST: ${local_fst_tmp})"
            rm -f "$local_fst_tmp" "${local_fst_tmp}.hier"
            exit 1
        fi
        rm -f "$local_fst_tmp" "${local_fst_tmp}.hier"
    else
        if ! run_with_stdout_mode "$SIM_LOG_VAN" \
            env SIMLEN="$SIMLEN" TRACEFILE="$VCD_VAN" \
            SIMSRAMELF="$ELF_A" \
            "$_active_vanilla_bin"
        then
            echo "WARNING: vanilla simulation (A) exited non-zero."
            [[ -s "$SIM_LOG_VAN" ]] && tail -20 "$SIM_LOG_VAN"
        fi
    fi
    if [[ "$SIM_STDOUT_MODE" != "quiet" ]]; then
        print_sim_log_summary "$SIM_LOG_VAN" "VAN"
    fi
    echo "  → ${VCD_VAN}  ($(du -sh "$VCD_VAN" 2>/dev/null | cut -f1) on disk)"
fi

echo ""

# ── Step 4: Instruction correlation ───────────────────────────────────────────
echo "── Step 4: Instruction correlation (pc_at_leakage.py) ───────"
python3 "${SCRIPT_DIR}/pc_at_leakage.py" \
    "$VCD_VAN" \
    "$ELF_A" \
    --cycles $CYCLES \
    --out-json "$INSTR_JSON"

echo ""

# ── Step 5: Vanilla VCD for key2 (data signal attribution) ───────────────────
echo "── Step 5: Vanilla VCD key2 (data attribution) ──────────────"
REGEN_VAN_B=0
if [[ -f "$VCD_VAN_B" ]]; then
    VCD_B_LAST_CYCLE="$(vcd_last_cycle "$VCD_VAN_B")"
    if [[ "$VCD_B_LAST_CYCLE" =~ ^-?[0-9]+$ ]] && (( VCD_B_LAST_CYCLE >= REQ_MAX_CYCLE )); then
        echo "  ↩  Key2 vanilla VCD already exists and covers requested cycles: ${VCD_VAN_B}"
        echo "     Coverage: up to cycle ${VCD_B_LAST_CYCLE}; requested max cycle ${REQ_MAX_CYCLE}."
    else
        echo "  ↻  Existing key2 vanilla VCD is too short (max cycle ${VCD_B_LAST_CYCLE}; need ${REQ_MAX_CYCLE})."
        REGEN_VAN_B=1
    fi
else
    REGEN_VAN_B=1
fi

if [[ "$REGEN_VAN_B" -eq 1 ]]; then
    echo "  Running key2 vanilla simulation (no taint, FST=${USE_VANILLA_FST})..."
    rm -f "$VCD_VAN_B"
    if [[ "$USE_VANILLA_FST" -eq 1 ]]; then
        local_fst_tmp_b="${VCD_VAN_B%.vcd}.fst"
        if ! run_with_stdout_mode "${TMP_ROOT}/vanilla_b.log" \
            env TMPDIR="${FST_TMPDIR:-/mnt/nvme1n1p1/tmp}" \
            SIMLEN="$SIMLEN" TRACEFILE="$local_fst_tmp_b" \
            SIMSRAMELF="$ELF_B" \
            "$_active_vanilla_bin"
        then
            echo "WARNING: vanilla simulation (B/key2) exited non-zero — FST may be incomplete."
            [[ -s "${TMP_ROOT}/vanilla_b.log" ]] && tail -20 "${TMP_ROOT}/vanilla_b.log"
        fi
        if [[ ! -s "$local_fst_tmp_b" ]]; then
            echo "ERROR: FST output missing or empty: ${local_fst_tmp_b}"
            rm -f "$local_fst_tmp_b" "${local_fst_tmp_b}.hier"
            echo "  Skipping Step 6 (no key2 VCD available)."
            REGEN_VAN_B=0
        else
            echo "  Converting FST → VCD ..."
            if ! fst2vcd "$local_fst_tmp_b" > "$VCD_VAN_B"; then
                echo "ERROR: fst2vcd failed for vanilla scenario B (FST: ${local_fst_tmp_b})"
                rm -f "$local_fst_tmp_b" "${local_fst_tmp_b}.hier" "$VCD_VAN_B"
                echo "  Skipping Step 6 (fst2vcd failed)."
                REGEN_VAN_B=0
            else
                rm -f "$local_fst_tmp_b" "${local_fst_tmp_b}.hier"
            fi
        fi
    else
        if ! run_with_stdout_mode "${TMP_ROOT}/vanilla_b.log" \
            env SIMLEN="$SIMLEN" TRACEFILE="$VCD_VAN_B" \
            SIMSRAMELF="$ELF_B" \
            "$_active_vanilla_bin"
        then
            echo "WARNING: vanilla simulation (B/key2) exited non-zero."
            [[ -s "${TMP_ROOT}/vanilla_b.log" ]] && tail -20 "${TMP_ROOT}/vanilla_b.log"
        fi
    fi
    if [[ "$REGEN_VAN_B" -eq 1 ]]; then
        echo "  → ${VCD_VAN_B}  ($(du -sh "$VCD_VAN_B" 2>/dev/null | cut -f1) on disk)"
    fi
fi

echo ""

# ── Step 6: Data signal attribution (vanilla VCD XOR) ────────────────────────
echo "── Step 6: Data signal attribution (leakage_signals_data.py) "
if [[ ! -f "$VCD_VAN_B" ]]; then
    echo "  SKIP: key2 vanilla VCD unavailable (Step 5 failed). Data attribution skipped."
else
    python3 "${SCRIPT_DIR}/leakage_signals_data.py" \
        "$VCD_VAN" "$VCD_VAN_B" \
        --cycles $CYCLES \
        --top 50 \
        --plot \
        --out "${OUT_PREFIX}_data" \
        --out-json "$DATA_SIGNAL_JSON"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Signal plots : ${OUT_PREFIX}_heatmap.png"
echo "                 ${OUT_PREFIX}_timeline.png"
echo "  Signal JSON  : ${SIGNAL_JSON}"
echo "  Data sig JSON: ${DATA_SIGNAL_JSON}"
echo "  Instr JSON   : ${INSTR_JSON}"
echo "  Vanilla VCD  : ${VCD_VAN}"
echo "════════════════════════════════════════════════════════════"
