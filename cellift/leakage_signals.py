#!/usr/bin/env python3
"""
leakage_signals.py — Identify which RTL signals carry key-dependent taint

Parses two VCD traces (Group A and Group B) and finds which _t0 (taint)
signals are nonzero and/or differ between the groups at specified simulation
cycles. This answers "which signals cause leakage and when?"

VCD time ↔ CSV cycle mapping (from testbench.h tick counting):
    CSV cycle N  →  VCD posedge timestamp = 35 + 5*N
    (6 reset ticks + 1 lead tick = 7; posedge = 5 * tick_count_)

Usage:
    # 1. Generate short VCDs covering the leakage window:
    ./run_cellift_sim.sh 100 traces/a.vcd scenario_aes128_unmasked_key1
    ./run_cellift_sim.sh 100 traces/b.vcd scenario_aes128_unmasked_key2

    # 2. Identify leaking signals at auto-detected divergence cycle:
    python3 leakage_signals.py traces/a.vcd traces/b.vcd

    # 3. Inspect specific cycles, top 30 signals, generate heatmap:
    python3 leakage_signals.py traces/a.vcd traces/b.vcd \\
        --cycles 36 40 50 --top 30 --plot --out unmasked_leakage

    # 4. Provide pre-computed CSVs to auto-select divergence cycles:
    python3 leakage_signals.py traces/a.vcd traces/b.vcd \\
        --csv-a tvla_unmasked_out/group_a.csv \\
        --csv-b tvla_unmasked_out/group_b.csv
"""

import argparse
import sys
import csv as _csv
import re
import json
from pathlib import Path
from collections import defaultdict

try:
    import numpy as np
    HAS_NP = True
except ImportError:
    HAS_NP = False

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


# ──────────────────────────────────────────────────────────────────────────────
# VCD timing
# ──────────────────────────────────────────────────────────────────────────────

RESET_TICKS  = 6   # reset() in testbench.h: tick(1) + tick(kResetLength=5)
LEAD_TICK    = 1   # first tick(1) before CSV cycle 0 is logged
TICK_BASE    = RESET_TICKS + LEAD_TICK   # = 7


def csv_cycle_to_vcd_time(cycle: int) -> int:
    """CSV cycle N → VCD posedge timestamp."""
    return 5 * (TICK_BASE + cycle)


def vcd_time_to_csv_cycle(t: int) -> int:
    """VCD posedge timestamp → CSV cycle N (−1 if not a posedge)."""
    if (t - 5 * TICK_BASE) % 5 == 0:
        return (t // 5) - TICK_BASE
    return -1


# ──────────────────────────────────────────────────────────────────────────────
# Streaming VCD parser — tracks only _t0 signals
# ──────────────────────────────────────────────────────────────────────────────

def parse_vcd(vcd_path: str, target_vcd_times: set) -> tuple:
    """
    Stream-parse a VCD file, extracting _t0 signal states at target timestamps.

    Returns:
        snapshots  : dict  {vcd_time -> {full_signal_path: int_value}}
        id_to_sig  : dict  {vcd_id   -> (full_path, width_bits)}
    """
    id_to_sig   = {}   # id → (full_path, width)
    scope_stack = []
    current_state = {}  # id → int value
    snapshots   = {t: None for t in target_vcd_times}

    # VCD value-change patterns
    RE_SCALAR = re.compile(r'^([01xzXZ])(.+)$')
    RE_VECTOR = re.compile(r'^[bBrR]([0-9a-fA-FxzXZ]+)\s+(.+)$')

    in_header = True
    current_time = 0

    print(f"  Parsing {vcd_path} …", flush=True)

    with open(vcd_path, 'r') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue

            # ── Header ──────────────────────────────────────────────────────
            if in_header:
                if line.startswith('$scope'):
                    parts = line.split()
                    if len(parts) >= 3:
                        scope_stack.append(parts[2])

                elif line.startswith('$upscope'):
                    if scope_stack:
                        scope_stack.pop()

                elif line.startswith('$var'):
                    # e.g.  $var wire 32 mo9! axi_arw_valid_t0 $end
                    #        $var wire 128 ro9! io_axi_w_payload_data_leak0 [127:0] $end
                    parts = line.split()
                    if len(parts) >= 5:
                        width   = int(parts[2])
                        var_id  = parts[3]
                        name    = parts[4]
                        # Track:
                        #   *_t0      — taint indicator bits (1 = node is tainted)
                        #   *_leak0   — data AND taint (key-dependent leakage value)
                        # Exclude _t0_leak0 (taint-of-taint, usually redundant)
                        is_t0_sig    = name.endswith('_t0')
                        is_leak0_sig = name.endswith('_leak0')
                        if is_t0_sig or is_leak0_sig:
                            full_path = '.'.join(scope_stack + [name])
                            if var_id not in id_to_sig:
                                id_to_sig[var_id] = (full_path, width,
                                                      'leak0' if is_leak0_sig else 't0')
                            current_state[var_id] = 0

                elif '$enddefinitions' in line:
                    in_header = False
                continue

            # ── Value changes ───────────────────────────────────────────────
            if line.startswith('#'):
                current_time = int(line[1:])
                # Snapshot at posedge timestamps
                if current_time in target_vcd_times:
                    snapshots[current_time] = {
                        id_to_sig[vid][0]: current_state[vid]
                        for vid in id_to_sig
                        if current_state.get(vid, 0) != 0
                    }
                continue

            # Vector value change:  bBINARY ID
            m = RE_VECTOR.match(line)
            if m:
                val_str, vid = m.group(1), m.group(2)
                if vid in id_to_sig:
                    try:
                        current_state[vid] = int(val_str.replace('x','0').replace('z','0'), 2)
                    except ValueError:
                        current_state[vid] = 0
                continue

            # Scalar value change:  0ID  or  1ID
            m = RE_SCALAR.match(line)
            if m:
                val_char, vid = m.group(1), m.group(2)
                if vid in id_to_sig:
                    current_state[vid] = 1 if val_char in '1' else 0

    # Fill any unvisited target times with empty dicts
    for t in target_vcd_times:
        if snapshots[t] is None:
            snapshots[t] = {}

    print(f"    Found {len(id_to_sig)} _t0 signals in header.")
    return snapshots, id_to_sig


# ──────────────────────────────────────────────────────────────────────────────
# CSV divergence detection
# ──────────────────────────────────────────────────────────────────────────────

def divergence_cycles_from_csvs(csv_a: str, csv_b: str,
                                 metric: str = 'hamming_weight_counter_t0') -> list:
    """Read per-cycle CSVs and return cycles where |A - B| > 0."""
    def load(path):
        rows = {}
        with open(path) as f:
            for row in _csv.DictReader(f):
                rows[int(row['cycle'])] = int(row[metric])
        return rows

    a, b = load(csv_a), load(csv_b)
    divs = sorted(c for c in a if c in b and abs(a[c] - b[c]) > 0)
    return divs


# ──────────────────────────────────────────────────────────────────────────────
# Signal comparison and reporting
# ──────────────────────────────────────────────────────────────────────────────

def compare_snapshots(snap_a: dict, snap_b: dict, id_to_sig: dict,
                       top_k: int = 20,
                       include_counters: bool = False) -> dict:
    """
    Compare two snapshots at a single cycle.
    Returns dict with 'leak0' and 't0' lists, each:
        (signal_name, width, val_a, val_b, xor_diff, hw_diff)
    sorted by descending Hamming weight of the difference.
    """
    # Build full_path → kind map
    path_to_kind = {}
    path_to_width = {}
    for (full_path, w, kind) in id_to_sig.values():
        path_to_kind[full_path] = kind
        path_to_width[full_path] = w

    all_sigs = set(snap_a) | set(snap_b)
    rows_leak0, rows_t0 = [], []

    # Aggregate counters are the pass's own per-module totals, not design nets,
    # so they must never compete with real signals in the per-net ranking. An
    # exact-name set misses every wrapper that prefixes or infixes them --
    # Proteus emits `pipeline_hamming_weight_counter_t0`, Ibex emits
    # `hamming_weight_counter_core_t0` -- so both cores were ranking their own
    # aggregate totals as if they were nets.
    aggregate_counter_re = re.compile(
        r'(hamming_weight_counter|hamming_distance_counter|leakage_counter)'
        r'(_[A-Za-z0-9]+)*_t0$')

    for sig in all_sigs:
        va = snap_a.get(sig, 0)
        vb = snap_b.get(sig, 0)
        if va == vb:
            continue
        diff = va ^ vb
        hw   = bin(diff).count('1')
        w    = path_to_width.get(sig, 1)
        kind = path_to_kind.get(sig, 't0')

        if (not include_counters) and kind == 't0':
            short = sig.split('.')[-1]
            if aggregate_counter_re.search(short):
                continue

        entry = (sig, w, va, vb, diff, hw)
        if kind == 'leak0':
            rows_leak0.append(entry)
        else:
            rows_t0.append(entry)

    rows_leak0.sort(key=lambda r: (-r[5], r[0]))
    rows_t0.sort(key=lambda r: (-r[5], r[0]))
    return {'leak0': rows_leak0[:top_k], 't0': rows_t0[:top_k]}


def _fmt_rows(rows, label):
    if not rows:
        return
    print(f"\n  ── {label} ──")
    print(f"  {'Signal':<52} {'W':>4} {'A (hex)':>18} {'B (hex)':>18} {'HW diff':>7}")
    print(f"  {'-'*52} {'-'*4} {'-'*18} {'-'*18} {'-'*7}")
    for sig, w, va, vb, diff, hw in rows:
        short = sig.split('.')[-1]
        # strip trailing scope noise for display
        scope_parts = sig.split('.')
        scope = scope_parts[-2] if len(scope_parts) > 1 else ''
        label_str = f"{short}"
        nbytes = max(1, (w + 3) // 4)
        MAX_HEX = 16  # cap display to avoid multi-MB lines for wide signals (e.g. mem arrays)
        va_s = format(va, 'x'); vb_s = format(vb, 'x')
        va_d = (va_s[:MAX_HEX] + '…') if len(va_s) > MAX_HEX else va_s.rjust(nbytes+2)
        vb_d = (vb_s[:MAX_HEX] + '…') if len(vb_s) > MAX_HEX else vb_s.rjust(nbytes+2)
        print(f"  {label_str:<52} {w:>4}  {va_d:>18}  {vb_d:>18}  {hw:>7}")


def print_comparison(cycle: int, result: dict):
    n_leak = len(result['leak0'])
    n_t0   = len(result['t0'])
    total  = n_leak + n_t0
    print(f"\n  Cycle {cycle}  (VCD time {csv_cycle_to_vcd_time(cycle)})"
          f"  —  {n_leak} _leak0 diffs, {n_t0} _t0 diffs")
    if total == 0:
        print("    (no differences — both groups have identical state)")
        return
    _fmt_rows(result['leak0'],
              "_leak0 signals  [data & taint — key-dependent leakage VALUE]")
    _fmt_rows(result['t0'],
              "_t0 signals     [taint topology — 1 = node is tainted]")


# ──────────────────────────────────────────────────────────────────────────────
# Heatmap plot
# ──────────────────────────────────────────────────────────────────────────────

def plot_heatmap(cycles: list, all_rows: dict, prefix: str, top_k: int):
    """
    Heatmap: x = simulation cycle, y = signal name, colour = HW(A XOR B).
    Signals shown are the union of top-K from all cycles, sorted by first
    appearance.
    """
    if not HAS_MPL or not HAS_NP:
        print("  matplotlib/numpy not found — skipping heatmap")
        return

    # Collect union of signal names across all cycles (_leak0 first, then _t0)
    sig_order = []
    seen = set()
    for cycle in cycles:
        result = all_rows.get(cycle) or {'leak0': [], 't0': []}
        for kind in ('leak0', 't0'):
            for (sig, w, va, vb, diff, hw) in result[kind]:
                if sig not in seen:
                    sig_order.append(sig)
                    seen.add(sig)
    if not sig_order:
        print("  No divergences found — skipping heatmap")
        return

    # Shorten signal names for display
    def short(s):
        parts = s.split('.')
        return parts[-1] if len(parts[-1]) > 3 else '.'.join(parts[-2:])

    labels = [short(s) for s in sig_order]

    # Build matrix: rows = signals, cols = cycles
    mat = np.zeros((len(sig_order), len(cycles)), dtype=np.int32)
    sig_idx = {s: i for i, s in enumerate(sig_order)}
    for j, cycle in enumerate(cycles):
        result = all_rows.get(cycle) or {'leak0': [], 't0': []}
        for kind in ('leak0', 't0'):
            for (sig, w, va, vb, diff, hw) in result[kind]:
                if sig in sig_idx:
                    mat[sig_idx[sig], j] = hw

    fig, ax = plt.subplots(figsize=(max(10, len(cycles) * 0.4 + 4),
                                    max(6,  len(sig_order) * 0.35 + 2)))
    im = ax.imshow(mat, aspect='auto', cmap='hot', origin='upper',
                   vmin=0, vmax=mat.max() or 1)
    plt.colorbar(im, ax=ax, label='Hamming weight of taint difference (A XOR B)')

    ax.set_xticks(range(len(cycles)))
    ax.set_xticklabels([str(c) for c in cycles], rotation=90, fontsize=7)
    ax.set_yticks(range(len(sig_order)))
    ax.set_yticklabels(labels, fontsize=7)
    ax.set_xlabel('Simulation cycle')
    ax.set_ylabel('_t0 signal')
    ax.set_title('CellIFT Key-Dependent Taint — Signal × Cycle Heatmap\n'
                 'Colour = Hamming weight of (Group A XOR Group B) taint value')

    plt.tight_layout()
    out = f"{prefix}_heatmap.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"\n  Heatmap saved → {out}")


def plot_timeline(cycles: list, all_rows: dict, prefix: str):
    """
    Bar chart of total diverging Hamming weight per cycle — shows the
    leakage intensity timeline.
    """
    if not HAS_MPL:
        return

    def _total_hw(c):
        r = all_rows.get(c) or {'leak0': [], 't0': []}
        return sum(x[5] for x in r['leak0']) + sum(x[5] for x in r['t0'])
    total_hw = [_total_hw(c) for c in cycles]

    fig, ax = plt.subplots(figsize=(max(10, len(cycles) * 0.3 + 4), 4))
    colors = ['crimson' if hw > 0 else 'steelblue' for hw in total_hw]
    ax.bar(cycles, total_hw, color=colors, width=0.8)
    ax.set_xlabel('Simulation cycle')
    ax.set_ylabel('Total HW(A XOR B) across all _t0 signals')
    ax.set_title('CellIFT Leakage Timeline — Total Key-Dependent Taint per Cycle')
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    out = f"{prefix}_timeline.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"  Timeline saved → {out}")


def write_signal_json(cycles: list, all_rows: dict, out_json: str):
    """Write per-cycle leaking signal rankings to JSON for downstream annotation."""
    data = {
        "metadata": {
            "cycles": [int(c) for c in cycles],
            "timing": {
                "reset_ticks": RESET_TICKS,
                "lead_tick": LEAD_TICK,
                "tick_base": TICK_BASE,
                "formula": "vcd_time = 5 * (tick_base + cycle)",
            },
        },
        "cycles": {},
    }

    for cycle in cycles:
        result = all_rows.get(cycle) or {"leak0": [], "t0": []}
        cycle_rows = []
        for kind in ("leak0", "t0"):
            for (sig, width, va, vb, diff, hw) in result[kind]:
                cycle_rows.append({
                    "kind": kind,
                    "signal": sig,
                    "width": int(width),
                    "hamming_weight_diff": int(hw),
                    "value_a_hex": hex(int(va)),
                    "value_b_hex": hex(int(vb)),
                })

        cycle_rows.sort(key=lambda x: (-x["hamming_weight_diff"], x["signal"]))
        data["cycles"][str(int(cycle))] = {
            "vcd_time": int(csv_cycle_to_vcd_time(cycle)),
            "top_signal": cycle_rows[0] if cycle_rows else None,
            "top_signals": cycle_rows,
        }

    path = Path(out_json)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    print(f"  Signal JSON    → {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Identify RTL _t0 signals with key-dependent taint',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('vcd_a', help='Group A VCD (e.g. from run_cellift_sim.sh)')
    ap.add_argument('vcd_b', help='Group B VCD')
    ap.add_argument('--cycles', type=int, nargs='+', metavar='N',
                    help='CSV cycle numbers to inspect (default: auto)')
    ap.add_argument('--csv-a', metavar='CSV',
                    help='Group A per-cycle CSV for auto divergence detection')
    ap.add_argument('--csv-b', metavar='CSV',
                    help='Group B per-cycle CSV for auto divergence detection')
    ap.add_argument('--top', type=int, default=20, metavar='K',
                    help='Report top K leaking signals per cycle (default: 20)')
    ap.add_argument('--include-counters', action='store_true',
                    help='Include aggregate *_counter_t0 signals in _t0 rankings')
    ap.add_argument('--plot', action='store_true',
                    help='Generate heatmap and timeline PNG plots')
    ap.add_argument('--out', default='leakage_signals', metavar='PREFIX',
                    help='Output file prefix (default: leakage_signals)')
    ap.add_argument('--out-json', default=None, metavar='PATH',
                    help='Write per-cycle top-signal JSON for annotation')
    args = ap.parse_args()

    # ── Determine cycles to inspect ─────────────────────────────────────────
    if args.cycles:
        cycles = sorted(set(args.cycles))
        print(f"Inspecting {len(cycles)} specified cycle(s): {cycles}")
    elif args.csv_a and args.csv_b:
        cycles = divergence_cycles_from_csvs(args.csv_a, args.csv_b)
        print(f"Auto-detected {len(cycles)} divergence cycles from CSVs.")
        if not cycles:
            print("No divergence cycles found — traces are identical.")
            sys.exit(0)
        # Limit to first 50 divergence cycles to keep VCD parsing tractable
        if len(cycles) > 50:
            print(f"  (capping at first 50 for signal analysis)")
            cycles = cycles[:50]
        print(f"  First: {cycles[0]}  Last: {cycles[-1]}")
    else:
        print("No --cycles or --csv-a/--csv-b given. Inspecting cycles 30–60.")
        cycles = list(range(30, 61))

    # ── Convert to VCD timestamps ────────────────────────────────────────────
    target_times = {csv_cycle_to_vcd_time(c) for c in cycles}
    time_to_cycle = {csv_cycle_to_vcd_time(c): c for c in cycles}

    # ── Parse both VCDs ──────────────────────────────────────────────────────
    snap_a, id_to_sig_a = parse_vcd(args.vcd_a, target_times)
    snap_b, id_to_sig_b = parse_vcd(args.vcd_b, target_times)

    # Merge id_to_sig (VCD IDs differ between files; full_path is consistent)
    # Each entry is (full_path, width, kind) where kind = 't0' or 'leak0'
    id_to_sig = {**id_to_sig_a, **id_to_sig_b}

    # ── Compare cycle by cycle ───────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  CellIFT Leakage Signal Report")
    print(f"  Group A: {args.vcd_a}")
    print(f"  Group B: {args.vcd_b}")
    print(f"{'='*70}")

    all_rows = {}   # cycle → comparison result dict
    leaky_cycles = []

    for t in sorted(target_times):
        cycle = time_to_cycle[t]
        sa = snap_a.get(t, {})
        sb = snap_b.get(t, {})
        result = compare_snapshots(sa, sb, id_to_sig,
                       top_k=args.top,
                       include_counters=args.include_counters)
        all_rows[cycle] = result
        if result['leak0'] or result['t0']:
            leaky_cycles.append(cycle)
            print_comparison(cycle, result)

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  Summary")
    print(f"{'='*70}")
    print(f"  Cycles inspected      : {len(cycles)}")
    print(f"  Cycles with leakage   : {len(leaky_cycles)}")
    if leaky_cycles:
        print(f"  First leakage cycle   : {leaky_cycles[0]}")

        sig_counts  = defaultdict(int)
        sig_hw_sum  = defaultdict(int)
        sig_kind    = {}
        for c in leaky_cycles:
            for kind in ('leak0', 't0'):
                for (sig, w, va, vb, diff, hw) in all_rows[c][kind]:
                    sig_counts[sig] += 1
                    sig_hw_sum[sig] += hw
                    sig_kind[sig] = kind

        ranked = sorted(sig_counts, key=lambda s: (-sig_hw_sum[s], s))

        print(f"\n  Top leaking signals (cumulative HW divergence, _leak0 first):")
        print(f"  {'Kind':<6} {'Signal':<50} {'Leaky cycles':>12}  {'Cumul HW':>10}")
        print(f"  {'-'*6} {'-'*50} {'-'*12}  {'-'*10}")
        for sig in ranked[:args.top]:
            short_name = sig.split('.')[-1]
            kind_tag = '[leak0]' if sig_kind.get(sig) == 'leak0' else '[t0]   '
            print(f"  {kind_tag}  {short_name:<50} {sig_counts[sig]:>12}  {sig_hw_sum[sig]:>10}")

    # ── Plots ────────────────────────────────────────────────────────────────
    if args.plot:
        print(f"\nGenerating plots …")
        plot_heatmap(cycles, all_rows, args.out, args.top)
        plot_timeline(cycles, all_rows, args.out)

    if args.out_json:
        write_signal_json(cycles, all_rows, args.out_json)

    print(f"\nDone.")


if __name__ == '__main__':
    main()
