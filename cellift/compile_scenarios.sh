#!/usr/bin/env bash
#
# compile_scenarios.sh — Batch-compile generated CellIFT AES scenarios.
#
# Finds every directory under sw/ whose name starts with PREFIX and runs
# `make` in each. Build output is captured to build.log in each directory.
# Reports pass/fail per scenario and exits non-zero if any build fails.
#
# Usage:
#   ./compile_scenarios.sh <PREFIX>
#
# Examples:
#   ./compile_scenarios.sh multi_aes_unmasked_a   # compiles sw/multi_aes_unmasked_a_*/
#   ./compile_scenarios.sh multi_aes_masked_b
#   ./compile_scenarios.sh scenario_aes128    # recompile reference scenarios

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${1:?Usage: compile_scenarios.sh <PREFIX>}"
SW_DIR="${SCRIPT_DIR}/sw"

# ── Find matching scenario directories ────────────────────────────────────────
mapfile -t dirs < <(find "$SW_DIR" -maxdepth 1 -type d -name "${PREFIX}*" | sort)

if [[ ${#dirs[@]} -eq 0 ]]; then
    echo "ERROR: no directories found matching sw/${PREFIX}*"
    echo "       Run gen_scenarios.py first, or check the prefix."
    exit 1
fi

echo "Compiling ${#dirs[@]} scenarios matching '${PREFIX}*'..."
echo ""

pass=0
fail=0
failed_names=()

for dir in "${dirs[@]}"; do
    name="$(basename "$dir")"
    log="${dir}/build.log"

    if make -C "$dir" --no-print-directory > "$log" 2>&1; then
        echo "  ✅  $name"
        pass=$((pass + 1))
    else
        echo "  ❌  $name  (see $log)"
        fail=$((fail + 1))
        failed_names+=("$name")
    fi
done

echo ""
echo "────────────────────────────────────────"
echo "  Compiled : ${pass} passed, ${fail} failed"

if [[ $fail -gt 0 ]]; then
    echo ""
    echo "  Failed scenarios:"
    for n in "${failed_names[@]}"; do
        echo "    - $n"
    done
    echo ""
    echo "  Tip: check the toolchain path in sw/<scenario>/Makefile"
    echo "       Expected: /mnt/nvme1n1p1/chipyard-1.11.0/.conda-env/riscv-tools/bin/"
    exit 1
fi
