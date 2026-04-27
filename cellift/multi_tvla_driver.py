#!/usr/bin/env python3
"""
multi_tvla_driver.py — TVLA analysis over N per-cycle leakage CSV files.

Loads all group_a_*.csv and group_b_*.csv files from a directory produced by
run_multi_trace_tvla.sh and runs two complementary analyses:

1. BETWEEN-GROUP DIFFERENTIAL (primary result)
   Compares the mean counter timeseries of Group A (key₁) vs Group B (key₂).
   This is the meaningful comparison: it reveals when and by how much the two
   keys produce different leakage patterns.  First divergence cycle and the
   magnitude of divergence are reported per counter.

2. WITHIN-GROUP VARIANCE CHECK
   Checks whether traces within each group are identical.

   For CellIFT's aggregate counters (LC, HW, HD), this will almost always be
   zero: the counters track *taint topology* (which signals are tainted), not
   data values.  Taint topology is determined by the key and the program
   structure — not by the plaintext.  Changing the plaintext with a fixed key
   therefore produces identical counter timeseries, so var = 0 within each
   group and the Welch t-statistic is undefined (NaN).

   This is expected and correct. The between-group comparison (analysis 1) is
   what demonstrates exploitable leakage.  A single trace per group is
   sufficient for CellIFT's aggregate counter approach; the multi-trace design
   is retained here to confirm the within-group consistency.

Usage:
    python3 multi_tvla_driver.py <OUTDIR> [options]

Arguments:
    OUTDIR          Directory containing group_a_*.csv and group_b_*.csv

Options:
    --threshold T   Welch |t| threshold for declaring leakage (default: 4.5)
    --plot          Generate PNG plots (requires matplotlib)
    --out PREFIX    Output file prefix (default: OUTDIR/welch)
    --delta         (no-op, kept for backward compat — counters are already per-cycle)
"""

import argparse
import sys
from pathlib import Path
from statistics import NormalDist

import numpy as np

# Import from tvla_analysis.py in the same directory
sys.path.insert(0, str(Path(__file__).parent))
from tvla_analysis import (
    load_csv, align, delta, welch_t,
    print_report, welch_report,
    COUNTERS, COUNTER_LABELS,
)

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


# ──────────────────────────────────────────────────────────────────────────────

def load_group(outdir: Path, group: str) -> list[dict]:
    """Load all CSV files for one group, sorted by index."""
    files = sorted(outdir.glob(f"group_{group}_*.csv"))
    if not files:
        sys.exit(f"ERROR: no group_{group}_*.csv files found in {outdir}")
    print(f"  Group {group.upper()}: {len(files)} traces", flush=True)
    return [load_csv(str(f)) for f in files]


def corrected_threshold(base_threshold: float, n_cycles: int,
                        method: str, alpha: float) -> float:
    """Return per-cycle |t| threshold after optional multiple-test correction."""
    if method == "none":
        return base_threshold
    if method != "bonferroni":
        raise ValueError(f"Unsupported correction method: {method}")
    # Two-sided test -> alpha / (2 * n_cycles)
    z = NormalDist().inv_cdf(1.0 - alpha / (2.0 * n_cycles))
    return max(base_threshold, float(z))


def align_all(traces_a: list, traces_b: list) -> tuple[list, list, np.ndarray]:
    """Trim all traces to the minimum common cycle count."""
    n = min(
        min(len(t["cycle"]) for t in traces_a),
        min(len(t["cycle"]) for t in traces_b),
    )
    traces_a = [{k: v[:n] for k, v in t.items()} for t in traces_a]
    traces_b = [{k: v[:n] for k, v in t.items()} for t in traces_b]
    return traces_a, traces_b, traces_a[0]["cycle"]


def mean_trace(traces: list, use_delta: bool) -> dict:
    """
    Return a synthetic trace whose counter values are the mean across all
    traces in the group.
    """
    result = {}
    for c in COUNTERS:
        if use_delta:
            stack = np.vstack([delta(t[c]) for t in traces])
        else:
            stack = np.vstack([t[c] for t in traces])
        result[c] = stack.mean(axis=0)
    result["cycle"] = traces[0]["cycle"]
    return result


def check_within_group_variance(traces: list, label: str) -> bool:
    """
    Check whether all traces in a group are identical (expected for CellIFT
    aggregate counters when only the plaintext varies).  Returns True if all
    traces are identical.
    """
    ref = traces[0]
    all_same = all(
        np.array_equal(t[c], ref[c])
        for t in traces[1:]
        for c in COUNTERS
    )
    if all_same:
        print(f"  ℹ  Group {label}: all {len(traces)} traces are identical "
              f"(expected — CellIFT counters depend on key, not plaintext).")
    else:
        print(f"  ✓  Group {label}: traces differ within group "
              f"(within-group variance > 0, Welch t-test meaningful).")
    return all_same


def between_group_report(traces_a: list, traces_b: list,
                         cycles: np.ndarray, prefix: str) -> dict:
    """
    Compare the first trace of each group (representative, since all are
    identical within a group when var=0) and return per-counter first-divergence
    info for the summary file.
    """
    print(f"\n── Between-group comparison (key₁ vs key₂) ─────────────────")
    summary = {}
    for c in COUNTERS:
        va = delta(traces_a[0][c])
        vb = delta(traces_b[0][c])
        absdiff = np.abs(va - vb)
        nz = np.nonzero(absdiff)[0]
        first = int(cycles[nz[0]]) if len(nz) else None
        nonzero = absdiff[absdiff > 0]
        print(f"  [{COUNTER_LABELS[c]}]")
        print(f"    First divergence cycle : {first if first is not None else 'none'}")
        if len(nonzero):
            print(f"    Leaking cycles         : {len(nonzero):,} of {len(cycles):,}")
            print(f"    Max  |A − B|           : {absdiff.max():,}")
        else:
            print(f"    No divergence detected.")
        print()
        summary[c] = {"first": first, "leaky": len(nonzero), "max_diff": int(absdiff.max()) if len(nonzero) else 0}
    return summary


def write_summary(outdir: Path, prefix: str, traces_a: list, traces_b: list,
                  cycles: np.ndarray, threshold: float,
                  threshold_raw: float, correction_method: str, alpha: float,
                  between_group: dict, within_identical: bool) -> None:
    """Write a machine-readable summary of TVLA findings."""
    lines = [
        "CellIFT TVLA Summary",
        f"N_A={len(traces_a)}  N_B={len(traces_b)}  cycles={len(cycles)}",
        f"within_group_identical={within_identical}",
        f"welch_threshold_raw={threshold_raw}",
        f"welch_threshold_effective={threshold:.6f}",
        f"multiple_comparison_correction={correction_method}",
        f"alpha={alpha}",
        "",
        "# Between-group comparison (key1 vs key2) — primary result",
    ]
    for c in COUNTERS:
        info = between_group[c]
        first = info['first'] if info['first'] is not None else 'none'
        lines += [
            f"[{c}]",
            f"  first_leaky_cycle = {first}",
            f"  leaky_cycle_count = {info['leaky']}",
            f"  max_diff          = {info['max_diff']}",
            "",
        ]

    if within_identical:
        suggested_prefix = str(outdir / "leakage")
        lines += [
            "# Welch t-test: not applicable",
            "#   All traces within each group are identical (var=0).",
            "#   This is expected: CellIFT aggregate counters (HW/HD/LC) depend",
            "#   on the key, not the plaintext.  Use between-group comparison above.",
            "#   For deterministic-safe per-cycle episodes/regimes run:",
            f"#   python3 cycle_leakage_quantifier.py {outdir} --plot --out {suggested_prefix}",
        ]
    else:
        lines += ["# Welch t-test results"]
        for c in COUNTERS:
            xa = np.vstack([delta(t[c])[:len(cycles)] for t in traces_a])
            xb = np.vstack([delta(t[c])[:len(cycles)] for t in traces_b])
            t_stat = welch_t(xa, xb)
            leaky  = cycles[t_stat > threshold]
            first  = int(leaky[0]) if len(leaky) else -1
            max_t  = float(np.nanmax(t_stat)) if not np.all(np.isnan(t_stat)) else float('nan')
            lines += [
                f"[{c}]",
                f"  first_leaky_cycle = {first if first >= 0 else 'none'}",
                f"  leaky_cycle_count = {len(leaky)}",
                f"  max_t             = {max_t:.4f}",
                "",
            ]

    summary_path = Path(prefix + "_summary.txt")
    summary_path.write_text("\n".join(lines))
    print(f"  Summary → {summary_path}")


# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("outdir",       help="Directory with group_a_*.csv / group_b_*.csv")
    ap.add_argument("--threshold",  type=float, default=4.5,
                    help="Welch |t| threshold (default: 4.5)")
    ap.add_argument("--mc-correction", choices=["none", "bonferroni"],
                    default="none",
                    help="Multiple-comparison correction mode for per-cycle Welch threshold")
    ap.add_argument("--alpha", type=float, default=0.05,
                    help="Family-wise alpha used when --mc-correction=bonferroni")
    ap.add_argument("--plot",       action="store_true",
                    help="Generate PNG plots (requires matplotlib)")
    ap.add_argument("--out",        default=None,
                    help="Output file prefix (default: OUTDIR/welch)")
    ap.add_argument("--delta",      action="store_true", default=True,
                    help="Backward-compatible flag. Counters are already per-cycle.")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    if not outdir.is_dir():
        sys.exit(f"ERROR: directory not found: {outdir}")

    prefix = args.out or str(outdir / "welch")

    # ── Load traces ───────────────────────────────────────────────────────────
    print(f"\nLoading traces from {outdir}...")
    traces_a = load_group(outdir, "a")
    traces_b = load_group(outdir, "b")

    if len(traces_a) < 2 or len(traces_b) < 2:
        sys.exit("ERROR: Welch t-test requires at least 2 traces per group.")

    traces_a, traces_b, cycles = align_all(traces_a, traces_b)
    print(f"  Aligned to {len(cycles)} cycles")

    if args.alpha <= 0.0 or args.alpha >= 1.0:
        sys.exit("ERROR: --alpha must be in (0, 1)")

    threshold_eff = corrected_threshold(args.threshold, len(cycles),
                                        args.mc_correction, args.alpha)
    print("\n── Significance configuration ───────────────────────────────")
    print(f"  Welch raw threshold          : {args.threshold}")
    print(f"  Multiple-comparison mode     : {args.mc_correction}")
    print(f"  Family-wise alpha            : {args.alpha}")
    print(f"  Welch effective threshold    : {threshold_eff:.6f}")

    # ── Within-group variance check ───────────────────────────────────────────
    print("\n── Within-group consistency check ───────────────────────────")
    ident_a = check_within_group_variance(traces_a, "A")
    ident_b = check_within_group_variance(traces_b, "B")
    within_identical = ident_a and ident_b

    # ── Between-group comparison (always meaningful) ───────────────────────────
    between = between_group_report(traces_a, traces_b, cycles, prefix)

    # ── Mean-trace differential report (full print_report output) ─────────────
    print("── Mean-trace differential report ───────────────────────────")
    ma = mean_trace(traces_a, use_delta=args.delta)
    mb = mean_trace(traces_b, use_delta=args.delta)
    print_report(ma, mb, cycles, use_delta=args.delta)

    # ── Welch t-test (only if within-group variance > 0) ──────────────────────
    if within_identical:
        print("\n── Welch t-test: skipped ────────────────────────────────────")
        print("  All traces within each group are identical (var = 0).")
        print("  This is expected: CellIFT's aggregate counters depend on the")
        print("  key topology, not the plaintext value.  The between-group")
        print("  comparison above is the meaningful result.")
        print("  Recommendation: run cycle_leakage_quantifier.py for")
        print("  det_leak/stoch_leak regime classification and episode timing.")
    else:
        print("\n── Welch t-test TVLA ────────────────────────────────────────")
        welch_report(traces_a, traces_b, cycles, prefix=prefix,
                     threshold=threshold_eff)

    # ── Summary file ──────────────────────────────────────────────────────────
    write_summary(outdir, prefix, traces_a, traces_b, cycles,
                  threshold_eff, args.threshold, args.mc_correction,
                  args.alpha, between, within_identical)

    # ── Mean-trace plot (overlaid A and B) ───────────────────────────────────
    if args.plot and HAS_MPL:
        _plot_mean_traces(ma, mb, cycles, prefix, args.delta)
    elif args.plot and not HAS_MPL:
        print("  matplotlib not available — skipping mean-trace plot")

    print(f"\nAll outputs written with prefix: {prefix}")


def _plot_mean_traces(ma: dict, mb: dict, cycles: np.ndarray,
                      prefix: str, use_delta: bool) -> None:
    n = len(COUNTERS)
    fig, axes = plt.subplots(n, 2, figsize=(16, 4 * n), squeeze=False)
    fig.suptitle("CellIFT Multi-Trace TVLA — Mean traces (Group A vs B)", fontsize=11)

    for row, c in enumerate(COUNTERS):
        va = delta(ma[c]) if use_delta else ma[c]
        vb = delta(mb[c]) if use_delta else mb[c]
        diff = va - vb
        absdiff = np.abs(diff)
        nz = np.nonzero(absdiff)[0]
        first = int(cycles[nz[0]]) if len(nz) else None

        ax = axes[row][0]
        ax.plot(cycles, va, color="steelblue",  lw=0.8, label="Group A (mean)")
        ax.plot(cycles, vb, color="darkorange", lw=0.8, label="Group B (mean)")
        if first is not None:
            ax.axvline(first, color="green", lw=1.0, ls="--",
                       label=f"1st divergence: cycle {first}")
        ax.set_title(f"{'Δ ' if use_delta else ''}{c}")
        ax.set_ylabel(COUNTER_LABELS[c])
        ax.set_xlabel("Simulation cycle")
        ax.legend(fontsize=7)
        ax.grid(alpha=0.25)

        ax2 = axes[row][1]
        ax2.fill_between(cycles, diff, 0, where=(diff > 0),
                         color="steelblue",  alpha=0.6, label="A > B")
        ax2.fill_between(cycles, diff, 0, where=(diff < 0),
                         color="darkorange", alpha=0.6, label="B > A")
        ax2.axhline(0, color="black", lw=0.5)
        if first is not None:
            ax2.axvline(first, color="green", lw=1.0, ls="--",
                        label=f"cycle {first}")
        ax2.set_title("Differential (mean A − mean B)")
        ax2.set_ylabel(f"A − B  [{COUNTER_LABELS[c].split('—')[0].strip()}]")
        ax2.set_xlabel("Simulation cycle")
        ax2.legend(fontsize=7)
        ax2.grid(alpha=0.25)

    plt.tight_layout()
    out = f"{prefix}_mean.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"  Mean-trace plot → {out}")
    plt.close()


if __name__ == "__main__":
    main()
