#!/usr/bin/env bash
#
# run_full_evaluation.sh - Core CellIFT TVLA pipeline (AES default).
#
# Flow:
#   0) Preflight
#   1) Scenario generation
#   2) Compilation
#   3) Multi-trace TVLA
#   4) Region discovery (pass 1)
#   5) Signal/instruction root-cause on diversified cycles
#   6) Quantification + annotated interval plots (pass 2)
#   7) Run manifest
#   8) Consolidated root-cause report
#   9) Publication summary

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
    cat <<'EOF'
Usage:
  ./run_full_evaluation.sh [options]

Options:
  --workload NAME        Workload profile for scenario generation (default: aes)
  --n-unmasked N         Traces/group for unmasked run (default: 20)
  --n-masked N           Traces/group for masked run (default: 100)
  --simlen N             Simulation cycles per trace (default: 30000)
  --seed N               Matched-pairs seed (default: 42)
    --jobs N               Parallel workers for simulations (default: auto-detected CPU count)
  --results DIR          Output root directory (default: ./results)
  --threshold T          Welch |t| threshold (default: 4.5)
  --window-len N         Fallback cycles after first leak if region selection empty (default: 5)
  --attr-cycles-max N    Max diversified attribution cycles for root-cause mapping (default: 24)
    --interval-top-k N     Top-K annotated intervals per counter (default: 8)
  --plot                 Enable dashboard/episode plots
  --no-interval-plots    Disable annotated interval plots
  --skip-preflight       Skip preflight checks
  --skip-gen             Skip scenario generation
  --skip-compile         Skip scenario compilation
  --skip-masked          Skip masked scenario generation, TVLA, and root-cause steps
  -h, --help             Show this help

Notes:
  - This script keeps only the core TVLA + root-cause + instruction mapping flow.
  - If --skip-gen or --skip-compile is used, generated scenarios and/or build artifacts
    must already exist for the selected workload and trace counts.
  - Use --skip-masked when the workload has no masked variant (e.g., kyber).
EOF
}

banner() {
    echo
    echo "============================================================"
    printf "  %s\n" "$1"
    echo "============================================================"
}

extract_first_cycle() {
    local summary_file="$1"
    local counter_name="$2"
    awk -v c="[$counter_name]" '
        $0 == c {in_block=1; next}
        in_block && /^\[/ {in_block=0}
        in_block && /first_leaky_cycle/ {
            gsub(/^[^=]*=[[:space:]]*/, "", $0)
            if ($0 != "none") { print $0; exit 0 }
        }
    ' "$summary_file"
}

build_cycle_window() {
    local first="$1"
    local length="$2"
    local i
    local out=""
    for ((i=0; i<length; i++)); do
        if [[ -n "$out" ]]; then
            out+=" "
        fi
        out+=$((first + i))
    done
    echo "$out"
}

max_cycle_in_list() {
    local cycles="$1"
    local max=-1
    local c
    for c in $cycles; do
        if [[ "$c" =~ ^[0-9]+$ ]] && [[ "$c" -gt "$max" ]]; then
            max="$c"
        fi
    done
    echo "$max"
}

select_cycles_from_regions() {
    local regions_json="$1"
    local max_cycles="$2"
    python3 - "$regions_json" "$max_cycles" <<'PY'
import json
import sys

path = sys.argv[1]
max_cycles = int(sys.argv[2])
with open(path) as f:
    data = json.load(f)

all_peaks = []
all_starts = []

# Prefer strict Welch intervals because they preserve narrower publication-grade
# peaks better than broad episode regions. Fall back to episode regions when needed.
for counter in (
    "leakage_counter_t0",
    "hamming_weight_counter_t0",
    "hamming_distance_counter_t0",
):
    c = data.get("counters", {}).get(counter, {})
    regions = c.get("strict_welch_regions", [])
    if not regions:
        regions = c.get("episode_regions", [])
    for r in regions:
        peak = int(r.get("peak_cycle", r.get("start_cycle", 0)))
        start = int(r.get("start_cycle", peak))
        mag = float(r.get("peak_magnitude", 0.0))
        all_peaks.append((peak, mag))
        all_starts.append((start, mag))

if not all_peaks:
    print("")
    raise SystemExit(0)

min_cycle = min(p for p, _ in all_peaks)
max_cycle = max(p for p, _ in all_peaks)
span = max(1, max_cycle - min_cycle + 1)

selected = set()
# Temporal stratification to avoid early-window domination.
bins = 4
bin_w = max(1, span // bins)
for b in range(bins):
    lo = min_cycle + b * bin_w
    hi = max_cycle if b == bins - 1 else (lo + bin_w - 1)
    cand = [(p, m) for p, m in all_peaks if lo <= p <= hi]
    if cand:
        p, _ = max(cand, key=lambda x: x[1])
        selected.add(p)

# Add strongest starts and peaks.
for p, _ in sorted(all_starts, key=lambda x: -x[1]):
    selected.add(p)
    if len(selected) >= max_cycles:
        break
for p, _ in sorted(all_peaks, key=lambda x: -x[1]):
    selected.add(p)
    if len(selected) >= max_cycles:
        break

out = sorted(selected)
print(" ".join(str(x) for x in out[:max_cycles]))
PY
}

N_UNMASKED=20
N_MASKED=100
SIMLEN=30000
SEED=42
if command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc)"
else
    JOBS=1
fi
WORKLOAD="aes"
RESULTS="$SCRIPT_DIR/results"
THRESHOLD=4.5
WINDOW_LEN=5
ATTR_CYCLES_MAX=24
INTERVAL_TOP_K=8
PLOT=0
PLOT_INTERVALS=1
SKIP_PREFLIGHT=0
SKIP_GEN=0
SKIP_COMPILE=0
SKIP_MASKED=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workload) WORKLOAD="$2"; shift 2 ;;
        --n-unmasked) N_UNMASKED="$2"; shift 2 ;;
        --n-masked) N_MASKED="$2"; shift 2 ;;
        --simlen) SIMLEN="$2"; shift 2 ;;
        --seed) SEED="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --results) RESULTS="$2"; shift 2 ;;
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --window-len) WINDOW_LEN="$2"; shift 2 ;;
        --attr-cycles-max) ATTR_CYCLES_MAX="$2"; shift 2 ;;
        --interval-top-k) INTERVAL_TOP_K="$2"; shift 2 ;;
        --plot) PLOT=1; shift ;;
        --no-interval-plots) PLOT_INTERVALS=0; shift ;;
        --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
        --skip-gen) SKIP_GEN=1; shift ;;
        --skip-compile) SKIP_COMPILE=1; shift ;;
        --skip-masked) SKIP_MASKED=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "ERROR: unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ ! "$N_UNMASKED" =~ ^[0-9]+$ ]] || [[ "$N_UNMASKED" -lt 2 ]]; then
    echo "ERROR: --n-unmasked must be >= 2"; exit 1
fi
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    if [[ ! "$N_MASKED" =~ ^[0-9]+$ ]] || [[ "$N_MASKED" -lt 2 ]]; then
        echo "ERROR: --n-masked must be >= 2"; exit 1
    fi
fi
if [[ ! "$SIMLEN" =~ ^[0-9]+$ ]] || [[ "$SIMLEN" -lt 20 ]]; then
    echo "ERROR: --simlen must be >= 20"; exit 1
fi
if [[ ! "$JOBS" =~ ^[0-9]+$ ]] || [[ "$JOBS" -lt 1 ]]; then
    echo "ERROR: --jobs must be >= 1"; exit 1
fi
if [[ ! "$WINDOW_LEN" =~ ^[0-9]+$ ]] || [[ "$WINDOW_LEN" -lt 1 ]]; then
    echo "ERROR: --window-len must be >= 1"; exit 1
fi
if [[ ! "$ATTR_CYCLES_MAX" =~ ^[0-9]+$ ]] || [[ "$ATTR_CYCLES_MAX" -lt 4 ]]; then
    echo "ERROR: --attr-cycles-max must be >= 4"; exit 1
fi
if [[ ! "$INTERVAL_TOP_K" =~ ^[0-9]+$ ]] || [[ "$INTERVAL_TOP_K" -lt 1 ]]; then
    echo "ERROR: --interval-top-k must be >= 1"; exit 1
fi

UNMASKED_A="multi_${WORKLOAD}_unmasked_a"
UNMASKED_B="multi_${WORKLOAD}_unmasked_b"
MASKED_A="multi_${WORKLOAD}_masked_a"
MASKED_B="multi_${WORKLOAD}_masked_b"

mkdir -p "$RESULTS"

TVLA_ARGS=("--threshold" "$THRESHOLD")
if [[ "$PLOT" -eq 1 ]]; then
    TVLA_ARGS+=("--plot")
fi

banner "Core TVLA Evaluation"
echo "workload      : $WORKLOAD"
echo "skip_masked   : $SKIP_MASKED"
echo "n_unmasked    : $N_UNMASKED"
echo "n_masked      : $N_MASKED"
echo "simlen        : $SIMLEN"
echo "seed          : $SEED"
echo "jobs          : $JOBS"
echo "threshold     : $THRESHOLD"
echo "results       : $RESULTS"
echo "attr_cycles   : $ATTR_CYCLES_MAX"
echo "interval_topk : $INTERVAL_TOP_K"
echo "interval_plot : $PLOT_INTERVALS"

if [[ "$SKIP_PREFLIGHT" -eq 0 ]]; then
    banner "Step 0 - Preflight"
    CHECK_SCENARIOS=0 ./run_eval_preflight.sh "$N_UNMASKED" "$N_MASKED"
fi

# Look up template scenario names from the workload profile (workload-aware).
UNMASKED_TEMPLATE_A="$(python3 -c "from gen_scenarios import WORKLOADS; print(WORKLOADS['${WORKLOAD}']['templates']['unmasked']['a'])")"
UNMASKED_TEMPLATE_B="$(python3 -c "from gen_scenarios import WORKLOADS; print(WORKLOADS['${WORKLOAD}']['templates']['unmasked']['b'])")"
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    MASKED_TEMPLATE_A="$(python3 -c "from gen_scenarios import WORKLOADS; print(WORKLOADS['${WORKLOAD}']['templates']['masked']['a'])")"
    MASKED_TEMPLATE_B="$(python3 -c "from gen_scenarios import WORKLOADS; print(WORKLOADS['${WORKLOAD}']['templates']['masked']['b'])")"
fi

if [[ "$SKIP_GEN" -eq 0 ]]; then
    banner "Step 1 - Generate Scenarios"
    python3 gen_scenarios.py --workload "$WORKLOAD" --type unmasked --group a --n "$N_UNMASKED" --seed "$SEED"
    python3 gen_scenarios.py --workload "$WORKLOAD" --type unmasked --group b --n "$N_UNMASKED" --seed "$SEED"
    if [[ "$SKIP_MASKED" -eq 0 ]]; then
        python3 gen_scenarios.py --workload "$WORKLOAD" --type masked --group a --n "$N_MASKED" --seed "$SEED"
        python3 gen_scenarios.py --workload "$WORKLOAD" --type masked --group b --n "$N_MASKED" --seed "$SEED"
    fi
fi

if [[ "$SKIP_COMPILE" -eq 0 ]]; then
    banner "Step 2 - Compile Scenarios"
    ./compile_scenarios.sh "$UNMASKED_A"
    ./compile_scenarios.sh "$UNMASKED_B"
    if [[ "$SKIP_MASKED" -eq 0 ]]; then
        ./compile_scenarios.sh "$MASKED_A"
        ./compile_scenarios.sh "$MASKED_B"
    fi
fi

banner "Step 3 - Multi-Trace TVLA"
JOBS="$JOBS" ./run_multi_trace_tvla.sh "$N_UNMASKED" "$SIMLEN" "$RESULTS/unmasked" "$UNMASKED_A" "$UNMASKED_B" "${TVLA_ARGS[@]}"
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    JOBS="$JOBS" ./run_multi_trace_tvla.sh "$N_MASKED" "$SIMLEN" "$RESULTS/masked" "$MASKED_A" "$MASKED_B" "${TVLA_ARGS[@]}"
fi

UNMASKED_SUMMARY="$RESULTS/unmasked/welch_summary.txt"
if [[ ! -f "$UNMASKED_SUMMARY" ]]; then
    echo "ERROR: expected unmasked TVLA summary file is missing"
    exit 1
fi
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    MASKED_SUMMARY="$RESULTS/masked/welch_summary.txt"
    if [[ ! -f "$MASKED_SUMMARY" ]]; then
        echo "ERROR: expected masked TVLA summary file is missing"
        exit 1
    fi
fi

UNMASKED_FIRST="$(extract_first_cycle "$UNMASKED_SUMMARY" "hamming_weight_counter_t0")"
[[ -z "$UNMASKED_FIRST" ]] && UNMASKED_FIRST=0
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    MASKED_FIRST="$(extract_first_cycle "$MASKED_SUMMARY" "hamming_weight_counter_t0")"
    [[ -z "$MASKED_FIRST" ]] && MASKED_FIRST=0
fi

banner "Step 4 - Region Discovery (Pass 1)"
python3 cycle_leakage_quantifier.py "$RESULTS/unmasked" --out "$RESULTS/unmasked/leakage"
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    python3 cycle_leakage_quantifier.py "$RESULTS/masked" --out "$RESULTS/masked/leakage"
fi

UNMASKED_CYCLES="$(select_cycles_from_regions "$RESULTS/unmasked/leakage_regions.json" "$ATTR_CYCLES_MAX")"
[[ -z "$UNMASKED_CYCLES" ]] && UNMASKED_CYCLES="$(build_cycle_window "$UNMASKED_FIRST" "$WINDOW_LEN")"
echo "Unmasked attribution cycles : $UNMASKED_CYCLES"
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    MASKED_CYCLES="$(select_cycles_from_regions "$RESULTS/masked/leakage_regions.json" "$ATTR_CYCLES_MAX")"
    [[ -z "$MASKED_CYCLES" ]] && MASKED_CYCLES="$(build_cycle_window "$MASKED_FIRST" "$WINDOW_LEN")"
    echo "Masked attribution cycles   : $MASKED_CYCLES"
fi

# Keep attribution VCD windows tight to selected cycles to avoid huge temporary files.
ATTR_MARGIN=64
UNMASKED_MAX_CYCLE="$(max_cycle_in_list "$UNMASKED_CYCLES")"
UNMASKED_ATTR_SIMLEN="$SIMLEN"
if [[ "$UNMASKED_MAX_CYCLE" -ge 0 ]]; then
    UNMASKED_ATTR_SIMLEN=$((UNMASKED_MAX_CYCLE + ATTR_MARGIN))
    if [[ "$UNMASKED_ATTR_SIMLEN" -gt "$SIMLEN" ]]; then
        UNMASKED_ATTR_SIMLEN="$SIMLEN"
    fi
fi
echo "Unmasked attribution simlen : $UNMASKED_ATTR_SIMLEN"
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    MASKED_MAX_CYCLE="$(max_cycle_in_list "$MASKED_CYCLES")"
    MASKED_ATTR_SIMLEN="$SIMLEN"
    if [[ "$MASKED_MAX_CYCLE" -ge 0 ]]; then
        MASKED_ATTR_SIMLEN=$((MASKED_MAX_CYCLE + ATTR_MARGIN))
        if [[ "$MASKED_ATTR_SIMLEN" -gt "$SIMLEN" ]]; then
            MASKED_ATTR_SIMLEN="$SIMLEN"
        fi
    fi
    echo "Masked attribution simlen   : $MASKED_ATTR_SIMLEN"
fi

banner "Step 5 - Root-Cause (Unmasked)"
./run_signal_correlation.sh \
    "$UNMASKED_TEMPLATE_A" \
    "$UNMASKED_TEMPLATE_B" \
    "$UNMASKED_CYCLES" "$UNMASKED_ATTR_SIMLEN" "$RESULTS/unmasked/signals_refined"
UNMASKED_SIGNAL_JSON="$RESULTS/unmasked/signals_refined_signals.json"
UNMASKED_INSTR_JSON="$RESULTS/unmasked/signals_refined_instructions.json"
UNMASKED_DATA_SIGNAL_JSON="$RESULTS/unmasked/signals_refined_data_signals.json"

if [[ "$SKIP_MASKED" -eq 0 ]]; then
    banner "Step 6 - Root-Cause (Masked)"
    ./run_signal_correlation.sh \
        "$MASKED_TEMPLATE_A" \
        "$MASKED_TEMPLATE_B" \
        "$MASKED_CYCLES" "$MASKED_ATTR_SIMLEN" "$RESULTS/masked/signals_refined"
    MASKED_SIGNAL_JSON="$RESULTS/masked/signals_refined_signals.json"
    MASKED_INSTR_JSON="$RESULTS/masked/signals_refined_instructions.json"
fi

banner "Step 7 - Per-Cycle Quantification (Pass 2 + Annotations)"
QARGS=()
if [[ "$PLOT" -eq 1 ]]; then
    QARGS+=("--plot")
fi
if [[ "$PLOT_INTERVALS" -eq 1 ]]; then
    QARGS+=("--plot-intervals" "--interval-top-k" "$INTERVAL_TOP_K")
fi
python3 cycle_leakage_quantifier.py "$RESULTS/unmasked" \
    --out "$RESULTS/unmasked/leakage" \
    --signal-json "$UNMASKED_SIGNAL_JSON" \
    --instruction-json "$UNMASKED_INSTR_JSON" \
    "${QARGS[@]}"
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    python3 cycle_leakage_quantifier.py "$RESULTS/masked" \
        --out "$RESULTS/masked/leakage" \
        --signal-json "$MASKED_SIGNAL_JSON" \
        --instruction-json "$MASKED_INSTR_JSON" \
        "${QARGS[@]}"
fi

banner "Step 8 - Run Manifest"
MANIFEST_PATH="$RESULTS/run_manifest_refined.json"
LEGACY_MANIFEST_PATH="$RESULTS/run_manifest.json"
if [[ "$SKIP_MASKED" -eq 0 ]]; then
cat > "$MANIFEST_PATH" <<EOF
{
  "pipeline": "core_tvla_root_cause",
  "workload": "${WORKLOAD}",
  "n_unmasked": ${N_UNMASKED},
  "n_masked": ${N_MASKED},
  "simlen": ${SIMLEN},
  "seed": ${SEED},
  "jobs": ${JOBS},
  "threshold_t": ${THRESHOLD},
  "window_len": ${WINDOW_LEN},
  "attr_cycles_max": ${ATTR_CYCLES_MAX},
  "interval_top_k": ${INTERVAL_TOP_K},
  "unmasked": {
    "first_hw_leak_cycle": ${UNMASKED_FIRST},
    "attribution_cycles": "${UNMASKED_CYCLES}",
    "attribution_simlen": ${UNMASKED_ATTR_SIMLEN},
    "signal_json": "${UNMASKED_SIGNAL_JSON}",
    "data_signal_json": "${UNMASKED_DATA_SIGNAL_JSON}",
    "instruction_json": "${UNMASKED_INSTR_JSON}",
    "regions_json": "${RESULTS}/unmasked/leakage_regions.json",
    "regions_csv": "${RESULTS}/unmasked/leakage_regions.csv"
  },
  "masked": {
    "first_hw_leak_cycle": ${MASKED_FIRST},
    "attribution_cycles": "${MASKED_CYCLES}",
    "attribution_simlen": ${MASKED_ATTR_SIMLEN},
    "signal_json": "${MASKED_SIGNAL_JSON}",
    "instruction_json": "${MASKED_INSTR_JSON}",
    "regions_json": "${RESULTS}/masked/leakage_regions.json",
    "regions_csv": "${RESULTS}/masked/leakage_regions.csv"
  }
}
EOF
else
cat > "$MANIFEST_PATH" <<EOF
{
  "pipeline": "core_tvla_root_cause",
  "workload": "${WORKLOAD}",
  "n_unmasked": ${N_UNMASKED},
  "simlen": ${SIMLEN},
  "seed": ${SEED},
  "jobs": ${JOBS},
  "threshold_t": ${THRESHOLD},
  "window_len": ${WINDOW_LEN},
  "attr_cycles_max": ${ATTR_CYCLES_MAX},
  "interval_top_k": ${INTERVAL_TOP_K},
  "unmasked": {
    "first_hw_leak_cycle": ${UNMASKED_FIRST},
    "attribution_cycles": "${UNMASKED_CYCLES}",
    "attribution_simlen": ${UNMASKED_ATTR_SIMLEN},
    "signal_json": "${UNMASKED_SIGNAL_JSON}",
    "data_signal_json": "${UNMASKED_DATA_SIGNAL_JSON}",
    "instruction_json": "${UNMASKED_INSTR_JSON}",
    "regions_json": "${RESULTS}/unmasked/leakage_regions.json",
    "regions_csv": "${RESULTS}/unmasked/leakage_regions.csv"
  }
}
EOF
fi
cp "$MANIFEST_PATH" "$LEGACY_MANIFEST_PATH"
echo "Run manifest               : $MANIFEST_PATH"
echo "Run manifest (legacy)      : $LEGACY_MANIFEST_PATH"

banner "Step 9 - Root-Cause Report"
REPORT_PREFIX="$RESULTS/root_cause_report_refined"
LEGACY_REPORT_PREFIX="$RESULTS/root_cause_report"
python3 generate_root_cause_report.py "$MANIFEST_PATH" --top-k "$INTERVAL_TOP_K" --out-prefix "$REPORT_PREFIX"
cp "${REPORT_PREFIX}.md" "${LEGACY_REPORT_PREFIX}.md"
cp "${REPORT_PREFIX}.json" "${LEGACY_REPORT_PREFIX}.json"

banner "Step 10 - Publication Summary"
python3 generate_publication_summary.py \
    "$MANIFEST_PATH" \
    "${REPORT_PREFIX}.json" \
    --out-prefix "$RESULTS/publication_summary_refined"

banner "Done"
echo "Unmasked first HW leakage cycle: $UNMASKED_FIRST"
if [[ "$SKIP_MASKED" -eq 0 ]]; then
    echo "Masked first HW leakage cycle  : $MASKED_FIRST"
fi
echo "Output root                    : $RESULTS"
