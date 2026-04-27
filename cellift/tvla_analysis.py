#!/usr/bin/env python3
"""
tvla_analysis.py — CellIFT per-cycle TVLA for Proteus masked AES-128

Loads per-cycle leakage counter CSVs produced by the run_cellift_csvlog
binary (one CSV per group) and analyses when and where key-dependent
information leakage occurs.

Each CSV row: cycle, leakage_counter_t0, hamming_weight_counter_t0,
                      hamming_distance_counter_t0

Counters are instantaneous per-cycle values (non-cumulative): each row
describes taint activity observed in that cycle only.

Usage:
    python3 tvla_analysis.py <csv_a> <csv_b> [options]

    --plot            Save PNG plots (requires matplotlib)
    --out PREFIX      Output file prefix (default: tvla)
    --trim-tail N     Ignore last N cycles (post-AES noise, default: 0)
    --delta           Legacy no-op (kept for backward compatibility)
"""

import argparse
import sys
import csv as _csv
from pathlib import Path

import numpy as np

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

# ──────────────────────────────────────────────────────────────────────────────
# Data loading
# ──────────────────────────────────────────────────────────────────────────────

COUNTERS = [
    "leakage_counter_t0",
    "hamming_weight_counter_t0",
    "hamming_distance_counter_t0",
]

COUNTER_LABELS = {
    "leakage_counter_t0":          "LC  — tainted nodes active",
    "hamming_weight_counter_t0":   "HW  — tainted bit-weight",
    "hamming_distance_counter_t0": "HD  — tainted bit-transitions",
}


def load_csv(path: str) -> dict:
    """Return dict: field_name → np.ndarray (int64)."""
    cols = {c: [] for c in ["cycle"] + COUNTERS}
    with open(path, newline="") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            for k in cols:
                cols[k].append(int(row[k]))
    return {k: np.array(v, dtype=np.int64) for k, v in cols.items()}


# ──────────────────────────────────────────────────────────────────────────────
# Analysis helpers
# ──────────────────────────────────────────────────────────────────────────────

def align(a: dict, b: dict, trim_tail: int = 0):
    """Trim both datasets to the same cycle range."""
    n = min(len(a["cycle"]), len(b["cycle"]))
    if trim_tail:
        n = max(0, n - trim_tail)
    return {k: a[k][:n] for k in a}, {k: b[k][:n] for k in b}, n


def delta(arr: np.ndarray) -> np.ndarray:
    """Identity — counters are already per-cycle (no diff needed)."""
    return arr


def first_nonzero_cycle(cycles: np.ndarray, arr: np.ndarray):
    idx = np.nonzero(arr)[0]
    return int(cycles[idx[0]]) if len(idx) else None


def welch_t(x: np.ndarray, y: np.ndarray) -> np.ndarray:
    """
    Per-position Welch t-statistic for two 2-D arrays (traces × cycles).
    Returns 1-D array of |t| per cycle.
    Requires at least 2 traces per group.
    """
    if x.ndim == 1:
        raise ValueError("Welch t-test needs multiple traces (2-D arrays).")
    n1, n2 = x.shape[0], y.shape[0]
    mu1, mu2 = x.mean(0), y.mean(0)
    v1 = x.var(0, ddof=1) / n1
    v2 = y.var(0, ddof=1) / n2
    denom = np.sqrt(v1 + v2)
    denom[denom == 0] = np.nan
    return np.abs((mu1 - mu2) / denom)


# ──────────────────────────────────────────────────────────────────────────────
# Text report
# ──────────────────────────────────────────────────────────────────────────────

def print_report(a: dict, b: dict, cycles: np.ndarray, use_delta: bool):
    label = "per-cycle (instantaneous)"
    print(f"\n{'─'*62}")
    print(f"  CellIFT TVLA Leakage Report  [{label}]")
    print(f"{'─'*62}")
    print(f"  Cycles compared : {len(cycles)}")
    print()

    for c in COUNTERS:
        va = delta(a[c]) if use_delta else a[c]
        vb = delta(b[c]) if use_delta else b[c]
        diff = va - vb
        absdiff = np.abs(diff)

        first = first_nonzero_cycle(cycles, absdiff)
        nonzero = absdiff[absdiff > 0]

        print(f"  [{COUNTER_LABELS[c]}]")
        print(f"    Group A final sample     : {a[c][-1]:>12,}")
        print(f"    Group B final sample     : {b[c][-1]:>12,}")
        print(f"    First divergence cycle   : {first if first is not None else 'none (identical traces!)'}")
        if len(nonzero):
            print(f"    Leakage cycles (|A−B|>0): {len(nonzero):>12,}  of {len(cycles):,}")
            print(f"    Max  |A − B|             : {absdiff.max():>12,}")
            print(f"    Mean |A − B| (leaky)     : {nonzero.mean():>12.1f}")
        else:
            print(f"    No divergence — traces are identical for this counter.")
        print()


# ──────────────────────────────────────────────────────────────────────────────
# Plotting
# ──────────────────────────────────────────────────────────────────────────────

def plot_traces(a: dict, b: dict, cycles: np.ndarray, prefix: str, use_delta: bool):
    if not HAS_MPL:
        print("  matplotlib not found — skipping plots (pip install matplotlib)")
        return

    n_counters = len(COUNTERS)
    fig, axes = plt.subplots(n_counters, 2, figsize=(16, 4 * n_counters), squeeze=False)
    fig.suptitle(
        "CellIFT TVLA — Masked AES-128  |  Proteus OoO Core\n"
        "Group A: key=2b7e151628aed2a6...  |  Group B: key=000102030405060708...",
        fontsize=11,
    )

    for row, c in enumerate(COUNTERS):
        va = delta(a[c]) if use_delta else a[c]
        vb = delta(b[c]) if use_delta else b[c]
        diff = va - vb
        absdiff = np.abs(diff)
        first = first_nonzero_cycle(cycles, absdiff)

        # ── Left: both group traces ──────────────────────────────────────────
        ax = axes[row][0]
        ax.plot(cycles, va, color="steelblue",  lw=0.7, label="Group A")
        ax.plot(cycles, vb, color="darkorange", lw=0.7, label="Group B")
        if first is not None:
            ax.axvline(first, color="green", lw=1.0, ls="--",
                       label=f"1st divergence: cycle {first}")
        ax.set_ylabel(COUNTER_LABELS[c])
        ax.set_title(f"{c}")
        ax.legend(fontsize=7, loc="upper left")
        ax.grid(alpha=0.25)
        ax.set_xlabel("Simulation cycle")

        # ── Right: differential A − B ────────────────────────────────────────
        ax2 = axes[row][1]
        ax2.fill_between(cycles, diff, 0,
                          where=(diff > 0), color="steelblue",  alpha=0.6, label="A > B")
        ax2.fill_between(cycles, diff, 0,
                          where=(diff < 0), color="darkorange", alpha=0.6, label="B > A")
        ax2.axhline(0, color="black", lw=0.6)
        if first is not None:
            ax2.axvline(first, color="green", lw=1.0, ls="--",
                        label=f"cycle {first}")
        ax2.set_ylabel(f"A − B  [{COUNTER_LABELS[c].split('—')[0].strip()}]")
        ax2.set_title(f"Differential (A − B)")
        ax2.legend(fontsize=7, loc="upper left")
        ax2.grid(alpha=0.25)
        ax2.set_xlabel("Simulation cycle")

    plt.tight_layout()
    out = f"{prefix}_tvla.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"  Plot saved → {out}")


# ──────────────────────────────────────────────────────────────────────────────
# Optional Welch t-test section (for multi-trace mode)
# ──────────────────────────────────────────────────────────────────────────────

def welch_report(traces_a: list, traces_b: list, cycles: np.ndarray,
                  prefix: str, threshold: float = 4.5):
    """
    Full Welch t-test TVLA over N traces per group.
    traces_a / traces_b: list of dicts (one per simulation run).
    """
    print(f"\n  Welch t-test TVLA  (|t| threshold = {threshold})")
    print(f"  Group A: {len(traces_a)} traces  |  Group B: {len(traces_b)} traces")
    print()

    if not HAS_MPL:
        print("  matplotlib not found — skipping t-test plots")

    n = len(cycles)

    if HAS_MPL:
        fig, axes = plt.subplots(len(COUNTERS), 2, figsize=(18, 4 * len(COUNTERS)), squeeze=False)
        fig.suptitle("CellIFT Welch t-test TVLA", fontsize=12)

    for row, c in enumerate(COUNTERS):
        xa = np.vstack([delta(t[c])[:n] for t in traces_a])
        xb = np.vstack([delta(t[c])[:n] for t in traces_b])
        t_stat = welch_t(xa, xb)

        leaky_cycles = cycles[t_stat > threshold]
        first = int(leaky_cycles[0]) if len(leaky_cycles) else None
        print(f"  [{c}]")
        print(f"    Cycles with |t| > {threshold}: {len(leaky_cycles):,}")
        print(f"    First leaky cycle          : {first if first is not None else 'none'}")
        print(f"    Max |t|                    : {np.nanmax(t_stat):.2f}")
        print()

        if HAS_MPL:
            finite = t_stat[np.isfinite(t_stat)]
            if finite.size:
                clip_max = np.percentile(finite, 99.5)
                clip_max = max(clip_max, threshold * 1.1)
                full_max = np.max(finite)
            else:
                clip_max = threshold * 1.1
                full_max = np.nan

            # Left panel: clipped y-range to expose smaller/later leakage episodes.
            ax = axes[row][0]
            ax.plot(cycles, t_stat, lw=0.7, color="purple")
            ax.axhline(threshold, color="red", lw=1.0, ls="--", label=f"|t|={threshold}")
            if first is not None:
                ax.axvline(first, color="green", lw=1.0, ls="--", label=f"cycle {first}")
            ax.set_ylabel("|t|-statistic")
            ax.set_title(f"{c} (clipped view)")
            ax.set_ylim(bottom=0, top=clip_max * 1.05)
            ax.legend(fontsize=8)
            ax.grid(alpha=0.25)
            ax.set_xlabel("Simulation cycle")

            # Right panel: full dynamic range for absolute maxima context.
            ax_full = axes[row][1]
            ax_full.plot(cycles, t_stat, lw=0.7, color="purple")
            ax_full.axhline(threshold, color="red", lw=1.0, ls="--", label=f"|t|={threshold}")
            if first is not None:
                ax_full.axvline(first, color="green", lw=1.0, ls="--", label=f"cycle {first}")
            ax_full.set_ylabel("|t|-statistic")
            ax_full.set_title(f"{c} (full range, max={full_max:.2f})")
            ax_full.legend(fontsize=8)
            ax_full.grid(alpha=0.25)
            ax_full.set_xlabel("Simulation cycle")

    if HAS_MPL:
        plt.tight_layout()
        out = f"{prefix}_welch.png"
        plt.savefig(out, dpi=150, bbox_inches="tight")
        print(f"  Welch plot saved → {out}")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="CellIFT TVLA — compare leakage counter CSVs between two simulation groups",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("csv_a", help="Group A per-cycle leakage CSV")
    ap.add_argument("csv_b", help="Group B per-cycle leakage CSV")
    ap.add_argument("--plot",       action="store_true", help="Generate PNG plots (requires matplotlib)")
    ap.add_argument("--out",        default="tvla",      help="Output prefix for plot files (default: tvla)")
    ap.add_argument("--trim-tail",  type=int, default=0, metavar="N",
                    help="Ignore last N cycles (post-AES idle, default: 0)")
    ap.add_argument("--delta",      action="store_true", default=True,
                    help="(no-op, kept for backward compat — counters are already per-cycle)")
    args = ap.parse_args()

    print(f"Loading Group A: {args.csv_a}")
    a = load_csv(args.csv_a)
    print(f"Loading Group B: {args.csv_b}")
    b = load_csv(args.csv_b)

    a, b, n = align(a, b, trim_tail=args.trim_tail)
    cycles = a["cycle"]
    print(f"Aligned to {n} cycles (trim_tail={args.trim_tail})")

    print_report(a, b, cycles, use_delta=args.delta)

    if args.plot:
        print("Generating plots...")
        plot_traces(a, b, cycles, args.out, use_delta=args.delta)

    print("Done.")


if __name__ == "__main__":
    main()
