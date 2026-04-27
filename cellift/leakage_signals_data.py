#!/usr/bin/env python3
"""
leakage_signals_data.py — Identify which RTL signals carry key-dependent DATA values

Compares two vanilla (untainted) VCDs at leakage cycles and ranks signals by
HW(XOR(val_key1, val_key2)).  Unlike leakage_signals.py (which compares _t0
taint topology), this script works on real signal values — effective even when
taint topology is key-independent (e.g. Ibex/Proteus Kyber NTT).

Usage:
    python3 leakage_signals_data.py vanilla_key1.vcd vanilla_key2.vcd \\
        --cycles 18351 18923 20119 \\
        --top 30 \\
        --plot \\
        --out results/unmasked/signals_data \\
        --out-json results/unmasked/signals_data_signals.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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
# VCD timing (same as leakage_signals.py)
# ──────────────────────────────────────────────────────────────────────────────

RESET_TICKS = 6
LEAD_TICK   = 1
TICK_BASE   = RESET_TICKS + LEAD_TICK  # = 7


def csv_cycle_to_vcd_time(cycle: int) -> int:
    return 5 * (TICK_BASE + cycle)


# ──────────────────────────────────────────────────────────────────────────────
# Default signal exclusion patterns
# ──────────────────────────────────────────────────────────────────────────────

# Signals that are constant, clock/reset, bus interface, or CellIFT artifacts.
# Excluded by default so the output focuses on CPU datapath signals.
_DEFAULT_EXCLUDE_PATTERNS = [
    # CellIFT taint/counter signals — handled by leakage_signals.py
    re.compile(r'_t0$'),
    re.compile(r'_leak0$'),
    # Clock, reset, test
    re.compile(r'^clk'),
    re.compile(r'clk_i$'),
    re.compile(r'rst_n'),
    re.compile(r'test_en'),
    re.compile(r'scan_'),
    re.compile(r'jtag_'),
    # TileLink bus signals (external interface, not maskable by designer)
    re.compile(r'^tl_'),
    re.compile(r'\.tl_'),
    # Escape / alert / lifecycle controller
    re.compile(r'esc_'),
    re.compile(r'lc_cpu_en'),
    re.compile(r'debug_req'),
    # Static configuration / package parameters (constant across runs)
    re.compile(r'ibex_pkg\.'),
    re.compile(r'tlul_pkg_'),
    re.compile(r'ram_cfg_i'),
    re.compile(r'boot_addr'),
    re.compile(r'hart_id'),
    # ROM / instruction memory address outputs (fixed by program, not key)
    re.compile(r'instr_mem_addr'),
    re.compile(r'instr_mem_req'),
    re.compile(r'instr_mem_gnt'),
    re.compile(r'instr_mem_rdata'),
    re.compile(r'instr_mem_strb'),
    re.compile(r'instr_mem_we'),
    re.compile(r'instr_rvalid'),
    # Memory grant / rvalid (external ack signals)
    re.compile(r'_gnt$'),
    re.compile(r'_rvalid'),
    # IRQ lines
    re.compile(r'irq_'),
    # Crash dump (debug artifact)
    re.compile(r'crash_dump'),
]


def _is_excluded(full_path: str, extra_patterns: List[re.Pattern]) -> bool:
    name = full_path.split('.')[-1]
    for pat in _DEFAULT_EXCLUDE_PATTERNS + extra_patterns:
        if pat.search(name) or pat.search(full_path):
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Streaming VCD parser — reads ALL non-excluded signals
# ──────────────────────────────────────────────────────────────────────────────

def parse_vcd(vcd_path: str,
              target_vcd_times: Set[int],
              extra_exclude: List[re.Pattern]) -> Tuple[dict, dict]:
    """
    Stream-parse a vanilla VCD, snapshotting all non-excluded signals at
    target_vcd_times.

    Returns:
        snapshots  : {vcd_time -> {full_signal_path: int_value}}
        id_to_sig  : {vcd_id   -> (full_path, width_bits)}
    """
    id_to_sig:    Dict[str, Tuple[str, int]] = {}
    scope_stack:  List[str] = []
    current_state: Dict[str, int] = {}
    snapshots = {t: None for t in target_vcd_times}

    RE_SCALAR = re.compile(r'^([01xzXZ])(.+)$')
    RE_VECTOR = re.compile(r'^[bBrR]([0-9a-fA-FxzXZ]+)\s+(.+)$')

    in_header   = True
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
                    parts = line.split()
                    if len(parts) >= 5:
                        width  = int(parts[2])
                        var_id = parts[3]
                        name   = parts[4]
                        full_path = '.'.join(scope_stack + [name])
                        if var_id not in id_to_sig and not _is_excluded(full_path, extra_exclude):
                            id_to_sig[var_id] = (full_path, width)
                            current_state[var_id] = 0

                elif '$enddefinitions' in line:
                    in_header = False
                continue

            # ── Value changes ────────────────────────────────────────────────
            if line.startswith('#'):
                current_time = int(line[1:])
                if current_time in target_vcd_times:
                    snapshots[current_time] = {
                        id_to_sig[vid][0]: current_state[vid]
                        for vid in id_to_sig
                        if current_state.get(vid, 0) != 0
                    }
                continue

            m = RE_VECTOR.match(line)
            if m:
                val_str, vid = m.group(1), m.group(2)
                if vid in id_to_sig:
                    try:
                        current_state[vid] = int(
                            val_str.replace('x', '0').replace('z', '0'), 2)
                    except ValueError:
                        current_state[vid] = 0
                continue

            m = RE_SCALAR.match(line)
            if m:
                val_char, vid = m.group(1), m.group(2)
                if vid in id_to_sig:
                    current_state[vid] = 1 if val_char == '1' else 0

    for t in target_vcd_times:
        if snapshots[t] is None:
            snapshots[t] = {}

    print(f"    Tracked {len(id_to_sig)} signals.", flush=True)
    return snapshots, id_to_sig


# ──────────────────────────────────────────────────────────────────────────────
# Comparison
# ──────────────────────────────────────────────────────────────────────────────

def compare_snapshots(snap_a: dict, snap_b: dict,
                      id_to_sig: dict, top_k: int) -> List[tuple]:
    """
    Compare snapshots at one cycle.  Returns list of
        (signal_path, width, val_a, val_b, xor_diff, hw_diff)
    sorted descending by hw_diff, capped at top_k.
    """
    # Build width lookup from merged id maps
    path_to_width: Dict[str, int] = {path: w for (path, w) in id_to_sig.values()}

    all_sigs = set(snap_a) | set(snap_b)
    rows: List[tuple] = []
    for sig in all_sigs:
        va = snap_a.get(sig, 0)
        vb = snap_b.get(sig, 0)
        if va == vb:
            continue
        diff = va ^ vb
        hw   = bin(diff).count('1')
        rows.append((sig, path_to_width.get(sig, 1), va, vb, diff, hw))

    rows.sort(key=lambda r: (-r[5], r[0]))
    return rows[:top_k]


# ──────────────────────────────────────────────────────────────────────────────
# Masking candidates summary
# ──────────────────────────────────────────────────────────────────────────────

def build_masking_candidates(cycles: List[int],
                              all_rows: Dict[int, List[tuple]]) -> List[dict]:
    """
    Aggregate per-cycle rows into a ranked masking candidate list.
    Each entry: signal path, width, total HW diff, count of leaky intervals.
    """
    hw_total: Dict[str, int] = defaultdict(int)
    interval_count: Dict[str, int] = defaultdict(int)
    widths: Dict[str, int] = {}

    for c in cycles:
        rows = all_rows.get(c, [])
        seen_this_cycle: Set[str] = set()
        for (sig, w, va, vb, diff, hw) in rows:
            hw_total[sig] += hw
            widths[sig] = w
            if sig not in seen_this_cycle:
                interval_count[sig] += 1
                seen_this_cycle.add(sig)

    ranked = sorted(hw_total, key=lambda s: (-hw_total[s], s))
    return [
        {
            "signal": sig,
            "width": widths[sig],
            "total_hw_diff": hw_total[sig],
            "leaky_interval_count": interval_count[sig],
        }
        for sig in ranked
    ]


# ──────────────────────────────────────────────────────────────────────────────
# Plots
# ──────────────────────────────────────────────────────────────────────────────

def plot_heatmap(cycles: List[int], all_rows: Dict[int, List[tuple]],
                 prefix: str, top_k: int) -> None:
    if not (HAS_MPL and HAS_NP):
        print("  matplotlib/numpy not available — skipping heatmap")
        return

    sig_order: List[str] = []
    seen: Set[str] = set()
    for c in cycles:
        for (sig, *_) in all_rows.get(c, []):
            if sig not in seen:
                sig_order.append(sig)
                seen.add(sig)
    if not sig_order:
        print("  No divergences found — skipping heatmap")
        return

    def _short(s: str) -> str:
        parts = s.split('.')
        return parts[-1] if len(parts[-1]) > 3 else '.'.join(parts[-2:])

    labels = [_short(s) for s in sig_order]
    mat = np.zeros((len(sig_order), len(cycles)), dtype=np.int32)
    sig_idx = {s: i for i, s in enumerate(sig_order)}
    for j, c in enumerate(cycles):
        for (sig, _, _va, _vb, _diff, hw) in all_rows.get(c, []):
            if sig in sig_idx:
                mat[sig_idx[sig], j] = hw

    fig, ax = plt.subplots(figsize=(max(10, len(cycles) * 0.4 + 4),
                                    max(6, len(sig_order) * 0.3 + 2)))
    im = ax.imshow(mat, aspect='auto', cmap='hot', origin='upper',
                   vmin=0, vmax=mat.max() or 1)
    plt.colorbar(im, ax=ax, label='HW(key1 XOR key2) per signal per cycle')
    ax.set_xticks(range(len(cycles)))
    ax.set_xticklabels([str(c) for c in cycles], rotation=90, fontsize=7)
    ax.set_yticks(range(len(sig_order)))
    ax.set_yticklabels(labels, fontsize=7)
    ax.set_xlabel('Simulation cycle')
    ax.set_ylabel('RTL signal')
    ax.set_title('Key-Dependent Signal Activity (Vanilla VCD XOR)\n'
                 'Colour = bits that differ between key1 and key2')
    plt.tight_layout()
    out = f"{prefix}_data_heatmap.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"  Heatmap saved → {out}")


def plot_timeline(cycles: List[int], all_rows: Dict[int, List[tuple]],
                  prefix: str) -> None:
    if not HAS_MPL:
        return
    total_hw = [sum(r[5] for r in all_rows.get(c, [])) for c in cycles]
    fig, ax = plt.subplots(figsize=(max(10, len(cycles) * 0.3 + 4), 4))
    colors = ['crimson' if hw > 0 else 'steelblue' for hw in total_hw]
    ax.bar(cycles, total_hw, color=colors, width=0.8)
    ax.set_xlabel('Simulation cycle')
    ax.set_ylabel('Total HW(key1 XOR key2) across all signals')
    ax.set_title('Key-Dependent Signal Activity Timeline')
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    out = f"{prefix}_data_timeline.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"  Timeline saved → {out}")


# ──────────────────────────────────────────────────────────────────────────────
# JSON output
# ──────────────────────────────────────────────────────────────────────────────

def write_signal_json(cycles: List[int], all_rows: Dict[int, List[tuple]],
                      masking_candidates: List[dict], out_json: str) -> None:
    data: dict = {
        "metadata": {
            "cycles": [int(c) for c in cycles],
            "timing": {
                "reset_ticks": RESET_TICKS,
                "lead_tick": LEAD_TICK,
                "tick_base": TICK_BASE,
                "formula": "vcd_time = 5 * (tick_base + cycle)",
            },
            "method": "vanilla_vcd_xor",
            "description": (
                "Key-dependent signal activity from vanilla VCD comparison. "
                "HW diff = number of bits that differ between key1 and key2 at that cycle."
            ),
        },
        "cycles": {},
        "masking_candidates": {
            "method": "vanilla_vcd_xor",
            "signals": masking_candidates,
        },
    }

    for c in cycles:
        rows = all_rows.get(c, [])
        cycle_rows = [
            {
                "kind": "data",
                "signal": sig,
                "width": int(w),
                "hamming_weight_diff": int(hw),
                "value_a_hex": hex(int(va)),
                "value_b_hex": hex(int(vb)),
            }
            for (sig, w, va, vb, _diff, hw) in rows
        ]
        data["cycles"][str(int(c))] = {
            "vcd_time": int(csv_cycle_to_vcd_time(c)),
            "top_signal": cycle_rows[0] if cycle_rows else None,
            "top_signals": cycle_rows,
        }

    path = Path(out_json)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    print(f"  Data signal JSON → {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description='Identify RTL signals with key-dependent DATA values (vanilla VCD XOR)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('vcd_a', help='Group A vanilla VCD (key1, no taint)')
    ap.add_argument('vcd_b', help='Group B vanilla VCD (key2, no taint)')
    ap.add_argument('--cycles', type=int, nargs='+', metavar='N',
                    help='CSV cycle numbers to inspect (required)')
    ap.add_argument('--top', type=int, default=20, metavar='K',
                    help='Top K signals to report per cycle (default: 20)')
    ap.add_argument('--plot', action='store_true',
                    help='Generate heatmap + timeline PNG plots')
    ap.add_argument('--out', default='signals_data', metavar='PREFIX',
                    help='Output file prefix for plots')
    ap.add_argument('--out-json', default=None, metavar='PATH',
                    help='Write per-cycle signal JSON (required for pipeline integration)')
    ap.add_argument('--exclude-pattern', nargs='+', default=[], metavar='REGEX',
                    help='Additional regex patterns to exclude signals (applied to full path)')
    args = ap.parse_args()

    if not args.cycles:
        ap.error('--cycles is required')

    cycles = sorted(set(args.cycles))
    print(f"Inspecting {len(cycles)} cycle(s): {cycles[:8]}{'...' if len(cycles) > 8 else ''}")

    extra_exclude = [re.compile(p) for p in args.exclude_pattern]
    target_times  = {csv_cycle_to_vcd_time(c) for c in cycles}
    time_to_cycle = {csv_cycle_to_vcd_time(c): c for c in cycles}

    snap_a, id_a = parse_vcd(args.vcd_a, target_times, extra_exclude)
    snap_b, id_b = parse_vcd(args.vcd_b, target_times, extra_exclude)

    # Merge id maps (signal paths are consistent across VCDs; IDs differ)
    id_to_sig = {**id_a, **id_b}

    print(f"\n{'='*70}")
    print(f"  Data Signal Leakage Report")
    print(f"  Key1 VCD : {args.vcd_a}")
    print(f"  Key2 VCD : {args.vcd_b}")
    print(f"{'='*70}")

    all_rows: Dict[int, List[tuple]] = {}
    leaky_cycles: List[int] = []

    for t in sorted(target_times):
        c = time_to_cycle[t]
        sa = snap_a.get(t, {})
        sb = snap_b.get(t, {})
        rows = compare_snapshots(sa, sb, id_to_sig, top_k=args.top)
        all_rows[c] = rows
        if rows:
            leaky_cycles.append(c)
            n = len(rows)
            print(f"\n  Cycle {c}  (VCD time {t})  —  {n} differing signal(s)")
            print(f"  {'Signal':<52} {'W':>4} {'Key1 (hex)':>18} {'Key2 (hex)':>18} {'HW diff':>7}")
            print(f"  {'-'*52} {'-'*4} {'-'*18} {'-'*18} {'-'*7}")
            for (sig, w, va, vb, _diff, hw) in rows:
                short = sig.split('.')[-1]
                nb = max(1, (w + 3) // 4)
                print(f"  {short:<52} {w:>4}  {va:>{nb+2}x}  {vb:>{nb+2}x}  {hw:>7}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  Summary")
    print(f"{'='*70}")
    print(f"  Cycles inspected   : {len(cycles)}")
    print(f"  Cycles with leakage: {len(leaky_cycles)}")

    masking_candidates = build_masking_candidates(cycles, all_rows)

    if masking_candidates:
        print(f"\n  Top masking candidates (cumulative HW divergence across all leaky cycles):")
        print(f"  {'Signal':<60} {'W':>4} {'Total HW':>9} {'Intervals':>9}")
        print(f"  {'-'*60} {'-'*4} {'-'*9} {'-'*9}")
        for entry in masking_candidates[:args.top]:
            short = entry['signal'].split('.')[-1]
            print(f"  {short:<60} {entry['width']:>4} {entry['total_hw_diff']:>9} {entry['leaky_interval_count']:>9}")
    else:
        print("  No key-dependent signal differences found.")
        print("  Check that --cycles are correct and that both VCDs cover those cycles.")

    if args.plot:
        print(f"\nGenerating plots …")
        plot_heatmap(cycles, all_rows, args.out, args.top)
        plot_timeline(cycles, all_rows, args.out)

    if args.out_json:
        write_signal_json(cycles, all_rows, masking_candidates, args.out_json)

    print(f"\nDone.")


if __name__ == '__main__':
    main()
