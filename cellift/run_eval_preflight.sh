#!/usr/bin/env bash
#
# run_eval_preflight.sh — Fail-fast checks before long CellIFT TVLA runs.
#
# Verifies required scripts, binaries, Python modules, and (optionally)
# scenario ELF/taint files for a requested trace count.
#
# Usage:
#   ./run_eval_preflight.sh [N_UNMASKED] [N_MASKED]
#
# Env:
#   CHECK_SCENARIOS=1   Validate sw/<scenario>/build/app.elf and taint_data files
#   STRICT=0            If 1, fail on optional utility script absence

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

N_UNMASKED="${1:-20}"
N_MASKED="${2:-100}"
CHECK_SCENARIOS="${CHECK_SCENARIOS:-1}"
STRICT="${STRICT:-0}"

ENV_SH="/mnt/nvme1n1p1/cellift-meta-leakage/env.sh"

required_scripts=(
  gen_scenarios.py
  compile_scenarios.sh
  run_multi_trace_tvla.sh
  multi_tvla_driver.py
  run_signal_correlation.sh
  run_full_evaluation.sh
  leakage_signals.py
  pc_at_leakage.py
  tvla_analysis.py
  cycle_leakage_quantifier.py
  generate_root_cause_report.py
)

optional_scripts=()

required_bins=(
  build/run_cellift_csvlog_0.1/default-verilator/Vproteus_tiny_soc
  build/run_cellift_fasttrace_0.1/default-verilator/Vproteus_tiny_soc
  build/run_vanilla_trace_0.1/default-verilator/Vproteus_tiny_soc
)

require_file() {
  local p="$1"
  if [[ ! -f "$p" ]]; then
    echo "ERROR: missing file: $p"
    return 1
  fi
  return 0
}

require_exec() {
  local p="$1"
  if [[ ! -x "$p" ]]; then
    echo "ERROR: missing executable: $p"
    return 1
  fi
  return 0
}

check_scenario_pair() {
  local prefix="$1"
  local n="$2"
  local fail=0
  local i idx sc elf taint

  for i in $(seq 0 $((n - 1))); do
    idx=$(printf "%03d" "$i")
    sc="${prefix}_${idx}"
    elf="sw/${sc}/build/app.elf"
    taint="taint_data/${sc}/taint_data.txt"

    if [[ ! -f "$elf" ]]; then
      echo "ERROR: missing ELF: $elf"
      fail=1
    fi
    if [[ ! -f "$taint" ]]; then
      echo "ERROR: missing taint file: $taint"
      fail=1
    fi
  done

  return "$fail"
}

resolve_scenario_prefix() {
  local preferred="$1"
  local legacy="$2"
  if [[ -d "sw/${preferred}_000" ]]; then
    echo "$preferred"
    return 0
  fi
  if [[ -d "sw/${legacy}_000" ]]; then
    echo "$legacy"
    return 0
  fi
  # Default to preferred name to keep error messages aligned with current flow.
  echo "$preferred"
}

echo "== CellIFT Evaluation Preflight =="
echo "  N_UNMASKED=${N_UNMASKED} N_MASKED=${N_MASKED} CHECK_SCENARIOS=${CHECK_SCENARIOS}"

if [[ ! -f "$ENV_SH" ]]; then
  echo "ERROR: env not found: $ENV_SH"
  exit 1
fi
source "$ENV_SH"

fail=0

for s in "${required_scripts[@]}"; do
  require_file "$SCRIPT_DIR/$s" || fail=1
done

for s in "${optional_scripts[@]}"; do
  if [[ ! -f "$SCRIPT_DIR/$s" ]]; then
    msg="WARN: optional script missing: $s"
    if [[ "$STRICT" == "1" ]]; then
      echo "ERROR: ${msg#WARN: }"
      fail=1
    else
      echo "$msg"
    fi
  fi
done

for b in "${required_bins[@]}"; do
  require_exec "$SCRIPT_DIR/$b" || fail=1
done

if ! python3 -c 'import numpy, csv, pathlib' >/dev/null 2>&1; then
  echo "ERROR: python3 modules missing (need at least numpy)"
  fail=1
fi

if [[ "$CHECK_SCENARIOS" == "1" ]]; then
  echo "  Checking scenario artifacts..."
  UNMASKED_A_PREFIX="$(resolve_scenario_prefix multi_aes_unmasked_a multi_unmasked_a)"
  UNMASKED_B_PREFIX="$(resolve_scenario_prefix multi_aes_unmasked_b multi_unmasked_b)"
  MASKED_A_PREFIX="$(resolve_scenario_prefix multi_aes_masked_a multi_masked_a)"
  MASKED_B_PREFIX="$(resolve_scenario_prefix multi_aes_masked_b multi_masked_b)"

  check_scenario_pair "$UNMASKED_A_PREFIX" "$N_UNMASKED" || fail=1
  check_scenario_pair "$UNMASKED_B_PREFIX" "$N_UNMASKED" || fail=1
  check_scenario_pair "$MASKED_A_PREFIX" "$N_MASKED" || fail=1
  check_scenario_pair "$MASKED_B_PREFIX" "$N_MASKED" || fail=1

  # Correlation scenarios used in step 4/5.
  for sc in \
    scenario_aes128_unmasked_key1 \
    scenario_aes128_unmasked_key2 \
    scenario_aes128_masked_key \
    scenario_aes128_masked_key2; do
    require_file "$SCRIPT_DIR/sw/${sc}/build/app.elf" || fail=1
    require_file "$SCRIPT_DIR/taint_data/${sc}/taint_data.txt" || fail=1
  done
fi

if [[ "$fail" -ne 0 ]]; then
  echo "Preflight FAILED"
  exit 1
fi

echo "Preflight PASSED"
