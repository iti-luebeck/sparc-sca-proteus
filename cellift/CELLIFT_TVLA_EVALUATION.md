# CellIFT TVLA Evaluation (Core-Only)

Target: Proteus OoO RISC-V core (RV32IM)
Scope: TVLA decision + root-cause signal analysis + instruction mapping

This guide keeps only the minimal workflow:
1. Run masked and unmasked AES TVLA
2. Detect leakage with Welch threshold
3. Identify switching/leaking RTL signals when leakage starts
4. Map leakage cycles to software instructions/source lines

## 1) Environment

```bash
source /mnt/nvme1n1p1/cellift-meta-leakage/env.sh
cd /mnt/nvme1n1p1/cellift-designs/cellift-proteus/cellift
```

## 2) Core Entry Point

```bash
./run_full_evaluation.sh --jobs 8 --plot
```

Main options:
- `--n-unmasked N` traces/group for unmasked AES (default `20`)
- `--n-masked N` traces/group for masked AES (default `100`)
- `--simlen N` simulation cycles (default `30000`)
- `--seed N` matched-pairs random seed (default `42`)
- `--threshold T` Welch threshold (default `4.5`)
- `--window-len N` number of cycles analyzed after first leakage cycle (default `5`)
- `--interval-top-k N` top annotated intervals per counter (default `3`)
- `--results DIR` output root directory
- `--workload NAME` scenario-generation profile (default `aes`)

## 3) What the Pipeline Runs

1. Scenario generation (`gen_scenarios.py`)
2. Scenario compilation (`compile_scenarios.sh`)
3. Multi-trace TVLA (`run_multi_trace_tvla.sh` + `multi_tvla_driver.py`)
4. Root-cause signal analysis (`run_signal_correlation.sh` + `leakage_signals.py`)
5. Instruction mapping (`pc_at_leakage.py`)
6. Per-cycle leakage quantification (`cycle_leakage_quantifier.py`)
7. Region extraction + overlap report (`cycle_leakage_quantifier.py`)
8. Annotated interval plots with signal+instruction attribution (`cycle_leakage_quantifier.py`)
9. Consolidated evidence report (`generate_root_cause_report.py`)

## 4) Output Layout

All outputs are written under `results/` (or `--results`).

- `results/unmasked/`
  - `group_a_*.csv`, `group_b_*.csv`
  - `welch_summary.txt`
  - `signals_heatmap.png`, `signals_timeline.png`
  - `leakage_*` quantifier outputs
  - `leakage_regions.json`, `leakage_regions.csv`
  - `leakage_*_interval_*_annotated.png`
- `results/masked/`
  - same output structure as unmasked
- `results/run_manifest.json`
  - run configuration + attribution artifact paths
- `results/root_cause_report.md`
  - publication-style summary of regions, overlap, and attributed intervals
- `results/root_cause_report.json`
  - machine-readable digest of the same evidence

Key interpretation fields from `welch_summary.txt`:
- `first_leaky_cycle`
- `leaky_cycle_count`
- `max_t` (Welch)

TVLA leakage criterion:
- cycle is leaky if `|t| > threshold` (default threshold `4.5`)

Region outputs include two bases:
- `episode` regions from regime timeline (`det_leak`/`stoch_leak`)
- `strict_welch` regions where `|t| > threshold`

`leakage_regions.json` reports overlap between both definitions (cycle intersection/union and Jaccard).

## 5) Root-Cause and Instruction Mapping

The pipeline automatically picks first leakage onset from TVLA summary and then analyzes a short cycle window.

Signal root-cause:
- compares CellIFT VCDs for Group A vs Group B
- ranks `_leak0`/switching signals at the selected cycles

Instruction mapping:
- reads vanilla VCD PC activity at leakage cycles
- maps PCs to disassembly/source location through ELF tools

Annotated interval plots:
- selected by Top-K peak `|t|`
- each plot includes: responsible signal, fetch instruction + PC, source line, regime tag, and peak metrics

## 6) AES Scenarios Kept

Reference scenarios retained:
- `sw/scenario_aes128_unmasked_key1`
- `sw/scenario_aes128_unmasked_key2`
- `sw/scenario_aes128_masked_key`
- `sw/scenario_aes128_masked_key2`

Generated matched-pair scenarios (created on demand by `run_full_evaluation.sh`):
- `sw/multi_aes_unmasked_a_*`, `sw/multi_aes_unmasked_b_*`
- `sw/multi_aes_masked_a_*`, `sw/multi_aes_masked_b_*`

Generation manifest:
- each generator call writes `sw/_manifests/multi_<workload>_<type>_<group>_manifest.json`
- includes per-trace seed, patched-label hashes, template provenance, and scenario list

## 7) Extending to New Workloads

Two extension points are kept:
1. Add workload profile in `gen_scenarios.py` (templates + patch labels)
2. Invoke with `./run_full_evaluation.sh --workload <name>`

Required profile contract:
- variants: `unmasked`, `masked`
- groups: `a`, `b`
- template scenarios must exist in `sw/` and matching taint folders in `taint_data/`

Generated naming convention:
- `multi_<workload>_<type>_<group>_<idx>`

## 8) Kept Core Scripts

- `run_full_evaluation.sh`
- `run_eval_preflight.sh`
- `gen_scenarios.py`
- `compile_scenarios.sh`
- `run_multi_trace_tvla.sh`
- `multi_tvla_driver.py`
- `run_signal_correlation.sh`
- `leakage_signals.py`
- `pc_at_leakage.py`
- `cycle_leakage_quantifier.py`
- `run_cellift_sim.sh`
- `run_vanilla_sim.sh`
