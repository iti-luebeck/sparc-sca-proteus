#!/usr/bin/env python3
"""
cycle_leakage_quantifier.py — Per-cycle leakage quantification for CellIFT TVLA.

Loads 2-group TVLA data (group_a_*.csv / group_b_*.csv) and computes per-cycle
leakage metrics that work for both deterministic divergence (zero within-group
variance) and stochastic divergence (nonzero variance).

Metrics per cycle:
  - Magnitude:  |mean_delta_A - mean_delta_B|
  - Cohen's d:  effect size (capped for deterministic divergence)
  - Welch |t|:  where within-group variance > 0 (NaN otherwise)
  - Regime:     det_leak / det_safe / stoch_leak / stoch_safe

Outputs:
  - Dashboard plot (magnitude, Cohen's d, Welch |t|, regime strip)
  - Per-cycle CSV
  - Episode summary JSON + text report

Usage:
    python3 cycle_leakage_quantifier.py <OUTDIR> [options]
"""

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from tvla_analysis import load_csv, delta, COUNTERS, COUNTER_LABELS

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import ListedColormap
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

# Regime labels
DET_LEAK = "det_leak"
DET_SAFE = "det_safe"
STOCH_LEAK = "stoch_leak"
STOCH_SAFE = "stoch_safe"

DET_CAP = 1000.0  # sentinel for deterministic divergence

COUNTER_SHORT = {
    "leakage_counter_t0": "lc",
    "hamming_weight_counter_t0": "hw",
    "hamming_distance_counter_t0": "hd",
}

COUNTER_FROM_SHORT = {v: k for k, v in COUNTER_SHORT.items()}


def fdr_bh(pvals):
    """Benjamini-Hochberg FDR correction with NaN preservation."""
    pvals = np.asarray(pvals, dtype=np.float64)
    out = np.full_like(pvals, np.nan)
    valid = np.where(np.isfinite(pvals))[0]
    if len(valid) == 0:
        return out

    pv = pvals[valid]
    order = np.argsort(pv)
    ranked = pv[order]
    m = float(len(ranked))

    q = ranked * (m / np.arange(1, len(ranked) + 1))
    q = np.minimum.accumulate(q[::-1])[::-1]
    q = np.clip(q, 0.0, 1.0)

    restored = np.empty_like(q)
    restored[order] = q
    out[valid] = restored
    return out


def _two_sided_sign_pvalue(n_pos, n_neg):
    """Two-sided sign-test p-value via normal approximation with continuity correction."""
    n_eff = n_pos + n_neg
    if n_eff <= 0:
        return np.nan
    k = min(n_pos, n_neg)
    mean = n_eff / 2.0
    sigma = math.sqrt(n_eff * 0.25)
    # Continuity correction for discrete binomial.
    z = (abs(k - mean) - 0.5) / sigma if sigma > 0 else 0.0
    z = max(z, 0.0)
    return float(math.erfc(z / math.sqrt(2.0)))


# ──────────────────────────────────────────────────────────────────────────────
# Data loading (reuses patterns from multi_tvla_driver.py)
# ──────────────────────────────────────────────────────────────────────────────

def load_group(outdir: Path, group: str) -> list:
    files = sorted(outdir.glob(f"group_{group}_*.csv"))
    if not files:
        sys.exit(f"ERROR: no group_{group}_*.csv files found in {outdir}")
    print(f"  Group {group.upper()}: {len(files)} traces", flush=True)
    return [load_csv(str(f)) for f in files]


def align_all(traces_a, traces_b):
    n = min(
        min(len(t["cycle"]) for t in traces_a),
        min(len(t["cycle"]) for t in traces_b),
    )
    traces_a = [{k: v[:n] for k, v in t.items()} for t in traces_a]
    traces_b = [{k: v[:n] for k, v in t.items()} for t in traces_b]
    return traces_a, traces_b, traces_a[0]["cycle"]


# ──────────────────────────────────────────────────────────────────────────────
# Core analysis
# ──────────────────────────────────────────────────────────────────────────────

def per_cycle_metrics(traces_a, traces_b, counter, cycles,
                      threshold_t=4.5, det_cap=DET_CAP):
    """
    Compute per-cycle leakage metrics for one counter.

    Returns dict with numpy arrays of shape (T,).
    """
    T = len(cycles)
    N_A = len(traces_a)
    N_B = len(traces_b)

    # Stack deltas: shape (N, T)
    XA = np.vstack([delta(t[counter])[:T].astype(np.float64) for t in traces_a])
    XB = np.vstack([delta(t[counter])[:T].astype(np.float64) for t in traces_b])

    mean_a = XA.mean(axis=0)
    mean_b = XB.mean(axis=0)
    magnitude = np.abs(mean_a - mean_b)

    # Within-group variance (pooled)
    if N_A > 1:
        var_a = XA.var(axis=0, ddof=1)
    else:
        var_a = np.zeros(T)
    if N_B > 1:
        var_b = XB.var(axis=0, ddof=1)
    else:
        var_b = np.zeros(T)

    var_within = np.where(
        (N_A > 1) & (N_B > 1),
        (var_a * (N_A - 1) + var_b * (N_B - 1)) / (N_A + N_B - 2),
        (var_a + var_b) / 2,
    )

    # Welch |t|
    welch_denom = np.sqrt(var_a / N_A + var_b / N_B)
    welch_denom_safe = np.where(welch_denom > 0, welch_denom, np.nan)
    welch_abs_t = np.abs((mean_a - mean_b) / welch_denom_safe)

    # Cohen's d
    pooled_std = np.sqrt(var_within)
    pooled_std_safe = np.where(pooled_std > 0, pooled_std, np.nan)
    cohens_d_raw = magnitude / pooled_std_safe
    # Cap deterministic divergence
    cohens_d = np.where(
        np.isnan(cohens_d_raw) & (magnitude > 0),
        det_cap,
        np.where(np.isnan(cohens_d_raw), 0.0, cohens_d_raw),
    )

    # Regime classification
    regime = np.full(T, DET_SAFE, dtype=object)
    for t in range(T):
        has_var = var_within[t] > 0
        has_mag = magnitude[t] > 0
        if not has_var and has_mag:
            regime[t] = DET_LEAK
        elif not has_var and not has_mag:
            regime[t] = DET_SAFE
        elif has_var and (not np.isnan(welch_abs_t[t]) and welch_abs_t[t] > threshold_t):
            regime[t] = STOCH_LEAK
        elif has_var and has_mag:
            # Magnitude exists but below Welch threshold — still flag if large
            regime[t] = STOCH_LEAK if magnitude[t] > 0 else STOCH_SAFE
        else:
            regime[t] = STOCH_SAFE

    return {
        "cycles": cycles,
        "XA": XA,
        "XB": XB,
        "mean_a": mean_a,
        "mean_b": mean_b,
        "magnitude": magnitude,
        "var_within": var_within,
        "cohens_d": cohens_d,
        "welch_t": welch_abs_t,
        "regime": regime,
    }


def paired_sign_test_per_cycle(metrics, alpha=0.05):
    """
    Paired sign test on per-trace cycle deltas.

    Uses matched pairs from XA/XB by index up to min(N_A, N_B), with ties dropped.
    """
    XA = metrics["XA"]
    XB = metrics["XB"]
    n_pairs = min(XA.shape[0], XB.shape[0])
    D = XA[:n_pairs, :] - XB[:n_pairs, :]

    n_pos = np.sum(D > 0, axis=0).astype(np.int64)
    n_neg = np.sum(D < 0, axis=0).astype(np.int64)
    n_eff = n_pos + n_neg

    pvals = np.array([
        _two_sided_sign_pvalue(int(n_pos[t]), int(n_neg[t]))
        for t in range(D.shape[1])
    ], dtype=np.float64)

    alpha_corr = alpha / max(1, D.shape[1])
    significant = np.isfinite(pvals) & (pvals < alpha_corr)

    return {
        "n_pairs": int(n_pairs),
        "n_pos": n_pos,
        "n_neg": n_neg,
        "n_eff": n_eff,
        "p_value": pvals,
        "alpha": float(alpha),
        "alpha_bonferroni": float(alpha_corr),
        "significant": significant,
    }


def paired_permutation_test_per_cycle(metrics, n_permutations=1000, seed=None, chunk_size=512):
    """
    Paired permutation test using random sign flips on matched-pair differences.

    The null assumes no consistent group direction, i.e., sign symmetry of D=XA-XB.
    """
    XA = metrics["XA"]
    XB = metrics["XB"]
    n_pairs = min(XA.shape[0], XB.shape[0])
    D = XA[:n_pairs, :] - XB[:n_pairs, :]
    T = D.shape[1]

    obs = np.abs(D.mean(axis=0))
    exceed = np.zeros(T, dtype=np.int64)
    null95 = np.zeros(T, dtype=np.float64)

    rng = np.random.default_rng(seed)
    signs = rng.choice(np.array([-1.0, 1.0], dtype=np.float64), size=(n_permutations, n_pairs))

    for start in range(0, T, chunk_size):
        end = min(T, start + chunk_size)
        d_chunk = D[:, start:end]
        null = np.abs((signs @ d_chunk) / float(n_pairs))
        exceed[start:end] = np.sum(null >= obs[start:end][None, :], axis=0)
        null95[start:end] = np.percentile(null, 95.0, axis=0)

    # Add +1 smoothing to avoid exact zero p-values.
    pvals = (exceed + 1.0) / (n_permutations + 1.0)
    pvals_fdr = fdr_bh(pvals)

    return {
        "n_pairs": int(n_pairs),
        "n_permutations": int(n_permutations),
        "observed_magnitude": obs,
        "p_value": pvals,
        "p_value_fdr": pvals_fdr,
        "null_95": null95,
    }


def enrich_episodes_with_det_tests(counter_result, cycles):
    """Attach optional sign/permutation aggregates to each episode."""
    episodes = counter_result["episodes"]
    sign = counter_result.get("sign_test")
    perm = counter_result.get("perm_test")
    if not episodes or (sign is None and perm is None):
        return

    cycle_to_idx = {int(c): i for i, c in enumerate(cycles)}

    for ep in episodes:
        s = cycle_to_idx.get(int(ep["start_cycle"]))
        e = cycle_to_idx.get(int(ep["end_cycle"]))
        if s is None or e is None or e < s:
            continue
        sl = slice(s, e + 1)

        if sign is not None:
            sig = sign["significant"][sl]
            p = sign["p_value"][sl]
            valid_p = p[np.isfinite(p)]
            ep["sign_test_n_sig"] = int(np.sum(sig))
            ep["sign_test_mean_p"] = float(np.mean(valid_p)) if len(valid_p) else None

        if perm is not None:
            p = perm["p_value"][sl]
            valid_p = p[np.isfinite(p)]
            obs = perm["observed_magnitude"][sl]
            n95 = perm["null_95"][sl]
            margin = obs - n95
            ep["perm_test_mean_p"] = float(np.mean(valid_p)) if len(valid_p) else None
            ep["perm_test_obs_vs_null95_peak"] = float(np.max(margin)) if len(margin) else None


def detect_episodes(metrics, min_gap=5):
    """
    Find contiguous leakage episodes (det_leak or stoch_leak).
    Merges episodes separated by fewer than min_gap safe cycles.
    """
    regime = metrics["regime"]
    cycles = metrics["cycles"]
    magnitude = metrics["magnitude"]
    cohens_d = metrics["cohens_d"]
    welch_t = metrics["welch_t"]

    leaky = np.array([r in (DET_LEAK, STOCH_LEAK) for r in regime])

    # Find contiguous runs
    raw_episodes = []
    in_ep = False
    for i in range(len(leaky)):
        if leaky[i] and not in_ep:
            start = i
            in_ep = True
        elif not leaky[i] and in_ep:
            raw_episodes.append((start, i - 1))
            in_ep = False
    if in_ep:
        raw_episodes.append((start, len(leaky) - 1))

    # Merge episodes with small gaps
    if not raw_episodes:
        return []

    merged = [raw_episodes[0]]
    for s, e in raw_episodes[1:]:
        prev_e = merged[-1][1]
        if s - prev_e <= min_gap:
            merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))

    # Characterize each episode
    episodes = []
    for s, e in merged:
        sl = slice(s, e + 1)
        mag_slice = magnitude[sl]
        peak_idx = s + int(np.argmax(mag_slice))

        det_count = sum(1 for r in regime[sl] if r == DET_LEAK)
        stoch_count = sum(1 for r in regime[sl] if r == STOCH_LEAK)
        dominant = DET_LEAK if det_count >= stoch_count else STOCH_LEAK

        peak_welch = float(welch_t[peak_idx])
        if np.isnan(peak_welch):
            # Find max welch in episode
            w_slice = welch_t[sl]
            valid_w = w_slice[~np.isnan(w_slice)]
            peak_welch = float(np.max(valid_w)) if len(valid_w) > 0 else None

        episodes.append({
            "start_cycle": int(cycles[s]),
            "end_cycle": int(cycles[e]),
            "duration": int(cycles[e] - cycles[s] + 1),
            "regime_dominant": dominant,
            "peak_magnitude": float(mag_slice.max()),
            "peak_cohens_d": float(cohens_d[sl].max()),
            "peak_welch_t": peak_welch,
            "peak_cycle": int(cycles[peak_idx]),
            "det_leak_cycles": det_count,
            "stoch_leak_cycles": stoch_count,
        })

    return episodes


# ──────────────────────────────────────────────────────────────────────────────
# Output: text report
# ──────────────────────────────────────────────────────────────────────────────

def print_counter_report(counter, metrics, episodes):
    short = COUNTER_SHORT[counter]
    label = COUNTER_LABELS[counter]
    regime = metrics["regime"]

    det_leak_count = sum(1 for r in regime if r == DET_LEAK)
    stoch_leak_count = sum(1 for r in regime if r == STOCH_LEAK)
    total_leak = det_leak_count + stoch_leak_count

    leaky_idx = [i for i, r in enumerate(regime) if r in (DET_LEAK, STOCH_LEAK)]
    first_cycle = int(metrics["cycles"][leaky_idx[0]]) if leaky_idx else None

    print(f"\n  [{label}]")
    print(f"    Total leaky cycles       : {total_leak:,} / {len(regime):,}"
          f"  (det={det_leak_count:,}, stoch={stoch_leak_count:,})")
    print(f"    First leaky cycle        : {first_cycle if first_cycle is not None else 'none'}")
    print(f"    Peak magnitude           : {metrics['magnitude'].max():.1f}")
    print(f"    Max Cohen's d            : {metrics['cohens_d'].max():.1f}")
    wt = metrics["welch_t"]
    valid_wt = wt[~np.isnan(wt)]
    if len(valid_wt):
        print(f"    Max Welch |t|            : {valid_wt.max():.1f}")
    else:
        print(f"    Max Welch |t|            : N/A (zero within-group variance)")
    print(f"    Episodes detected        : {len(episodes)}")

    if episodes:
        print(f"\n    {'Episode':>8} {'Cycles':>16} {'Dur':>5} {'Regime':>12}"
              f" {'Peak mag':>10} {'Peak d':>8} {'Peak |t|':>10}")
        for i, ep in enumerate(episodes):
            wt_str = f"{ep['peak_welch_t']:.1f}" if ep["peak_welch_t"] is not None else "N/A"
            print(f"    {i:>8} {ep['start_cycle']:>7}-{ep['end_cycle']:<7}"
                  f" {ep['duration']:>5} {ep['regime_dominant']:>12}"
                  f" {ep['peak_magnitude']:>10.1f} {ep['peak_cohens_d']:>8.1f}"
                  f" {wt_str:>10}")

            extras = []
            if "sign_test_n_sig" in ep:
                pstr = (f"{ep['sign_test_mean_p']:.3g}"
                        if ep.get("sign_test_mean_p") is not None else "N/A")
                extras.append(f"sign-sig={ep['sign_test_n_sig']}, sign-p-mean={pstr}")
            if "perm_test_mean_p" in ep:
                pstr = (f"{ep['perm_test_mean_p']:.3g}"
                        if ep.get("perm_test_mean_p") is not None else "N/A")
                mstr = (f"{ep['perm_test_obs_vs_null95_peak']:.2f}"
                        if ep.get("perm_test_obs_vs_null95_peak") is not None else "N/A")
                extras.append(f"perm-p-mean={pstr}, peak(obs-null95)={mstr}")
            if extras:
                print(f"             det-safe stats      : {'; '.join(extras)}")


# ──────────────────────────────────────────────────────────────────────────────
# Output: CSV
# ──────────────────────────────────────────────────────────────────────────────

def write_per_cycle_csv(all_results, cycles, prefix):
    path = Path(f"{prefix}_per_cycle.csv")
    T = len(cycles)

    headers = ["cycle"]
    for counter in COUNTERS:
        short = COUNTER_SHORT[counter]
        if counter not in all_results:
            continue
        headers += [f"{short}_magnitude", f"{short}_cohens_d",
                    f"{short}_welch_t", f"{short}_regime"]
        if "sign_test" in all_results[counter]:
            headers += [f"{short}_sign_n_pos", f"{short}_sign_n_neg",
                        f"{short}_sign_p", f"{short}_sign_sig"]
        if "perm_test" in all_results[counter]:
            headers += [f"{short}_perm_p", f"{short}_perm_p_fdr",
                        f"{short}_perm_null95"]

    with open(path, "w") as f:
        f.write(",".join(headers) + "\n")
        for t in range(T):
            row = [str(int(cycles[t]))]
            for counter in COUNTERS:
                if counter not in all_results:
                    continue
                m = all_results[counter]["metrics"]
                short = COUNTER_SHORT[counter]
                mag = m["magnitude"][t]
                cd = m["cohens_d"][t]
                wt = m["welch_t"][t]
                rg = m["regime"][t]
                row.append(f"{mag:.4f}")
                row.append(f"{cd:.4f}")
                row.append(f"{wt:.4f}" if not np.isnan(wt) else "nan")
                row.append(rg)
                if "sign_test" in all_results[counter]:
                    s = all_results[counter]["sign_test"]
                    row.append(str(int(s["n_pos"][t])))
                    row.append(str(int(s["n_neg"][t])))
                    sp = s["p_value"][t]
                    row.append(f"{sp:.6g}" if np.isfinite(sp) else "nan")
                    row.append("1" if bool(s["significant"][t]) else "0")
                if "perm_test" in all_results[counter]:
                    p = all_results[counter]["perm_test"]
                    pp = p["p_value"][t]
                    pf = p["p_value_fdr"][t]
                    n95 = p["null_95"][t]
                    row.append(f"{pp:.6g}" if np.isfinite(pp) else "nan")
                    row.append(f"{pf:.6g}" if np.isfinite(pf) else "nan")
                    row.append(f"{n95:.6g}")
            f.write(",".join(row) + "\n")

    print(f"  Per-cycle CSV  -> {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Output: JSON
# ──────────────────────────────────────────────────────────────────────────────

def write_episodes_json(all_results, cycles, n_a, n_b, prefix):
    path = Path(f"{prefix}_episodes.json")

    data = {
        "metadata": {
            "N_A": n_a,
            "N_B": n_b,
            "total_cycles": int(len(cycles)),
            "first_cycle": int(cycles[0]),
            "last_cycle": int(cycles[-1]),
        },
        "counters": {},
    }

    for counter in COUNTERS:
        if counter not in all_results:
            continue
        m = all_results[counter]["metrics"]
        eps = all_results[counter]["episodes"]
        regime = m["regime"]

        det_count = sum(1 for r in regime if r == DET_LEAK)
        stoch_count = sum(1 for r in regime if r == STOCH_LEAK)
        leaky_idx = [i for i, r in enumerate(regime) if r in (DET_LEAK, STOCH_LEAK)]
        first = int(cycles[leaky_idx[0]]) if leaky_idx else None

        data["counters"][counter] = {
            "total_leaky_cycles": det_count + stoch_count,
            "det_leak_cycles": det_count,
            "stoch_leak_cycles": stoch_count,
            "first_leaky_cycle": first,
            "peak_magnitude": float(m["magnitude"].max()),
            "episodes": eps,
        }
        if "sign_test" in all_results[counter]:
            s = all_results[counter]["sign_test"]
            data["counters"][counter]["sign_test"] = {
                "n_pairs": int(s["n_pairs"]),
                "alpha": float(s["alpha"]),
                "alpha_bonferroni": float(s["alpha_bonferroni"]),
                "significant_cycles": int(np.sum(s["significant"])),
            }
        if "perm_test" in all_results[counter]:
            p = all_results[counter]["perm_test"]
            data["counters"][counter]["perm_test"] = {
                "n_pairs": int(p["n_pairs"]),
                "n_permutations": int(p["n_permutations"]),
                "min_p_value": float(np.nanmin(p["p_value"])),
                "min_p_value_fdr": float(np.nanmin(p["p_value_fdr"])),
            }

    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(f"  Episodes JSON  -> {path}")


def strict_welch_regions(metrics, threshold_t=4.5):
    """Build contiguous strict-threshold regions where Welch |t| > threshold_t."""
    cycles = metrics["cycles"]
    welch = metrics["welch_t"]
    magnitude = metrics["magnitude"]
    cohens_d = metrics["cohens_d"]

    active = np.array([np.isfinite(w) and (w > threshold_t) for w in welch], dtype=bool)
    regions = []
    i = 0
    while i < len(active):
        if not active[i]:
            i += 1
            continue
        s = i
        while i + 1 < len(active) and active[i + 1]:
            i += 1
        e = i

        sl = slice(s, e + 1)
        peak_rel = int(np.argmax(welch[sl]))
        peak_idx = s + peak_rel
        regions.append({
            "start_cycle": int(cycles[s]),
            "end_cycle": int(cycles[e]),
            "duration": int(cycles[e] - cycles[s] + 1),
            "peak_cycle": int(cycles[peak_idx]),
            "peak_welch_t": float(welch[peak_idx]),
            "peak_magnitude": float(np.max(magnitude[sl])),
            "peak_cohens_d": float(np.max(cohens_d[sl])),
        })
        i += 1
    return regions


def _cycles_from_regions(regions):
    s = set()
    for r in regions:
        s.update(range(int(r["start_cycle"]), int(r["end_cycle"]) + 1))
    return s


def write_regions_outputs(all_results, cycles, prefix, threshold_t):
    """Write dual-basis regions and overlap statistics to JSON + CSV."""
    json_path = Path(f"{prefix}_regions.json")
    csv_path = Path(f"{prefix}_regions.csv")

    out = {
        "metadata": {
            "first_cycle": int(cycles[0]),
            "last_cycle": int(cycles[-1]),
            "total_cycles": int(len(cycles)),
            "welch_threshold": float(threshold_t),
            "region_bases": ["episode", "strict_welch"],
        },
        "counters": {},
    }

    csv_lines = [
        "counter,basis,region_id,start_cycle,end_cycle,duration,peak_cycle,peak_magnitude,peak_cohens_d,peak_welch_t,regime"
    ]

    for counter in COUNTERS:
        if counter not in all_results:
            continue
        metrics = all_results[counter]["metrics"]
        episodes = all_results[counter]["episodes"]
        strict = strict_welch_regions(metrics, threshold_t=threshold_t)

        cyc_episode = _cycles_from_regions(episodes)
        cyc_strict = _cycles_from_regions(strict)
        inter = cyc_episode & cyc_strict
        union = cyc_episode | cyc_strict
        overlap = {
            "episode_cycle_count": int(len(cyc_episode)),
            "strict_cycle_count": int(len(cyc_strict)),
            "intersection_cycle_count": int(len(inter)),
            "union_cycle_count": int(len(union)),
            "jaccard": (float(len(inter)) / float(len(union)) if len(union) else 0.0),
            "strict_covered_by_episode": (float(len(inter)) / float(len(cyc_strict)) if len(cyc_strict) else 0.0),
            "episode_covered_by_strict": (float(len(inter)) / float(len(cyc_episode)) if len(cyc_episode) else 0.0),
        }

        out["counters"][counter] = {
            "episode_regions": episodes,
            "strict_welch_regions": strict,
            "overlap": overlap,
        }

        for i, r in enumerate(episodes):
            csv_lines.append(
                f"{counter},episode,{i},{r['start_cycle']},{r['end_cycle']},{r['duration']},{r['peak_cycle']},"
                f"{r['peak_magnitude']:.6g},{r['peak_cohens_d']:.6g},{(r['peak_welch_t'] if r['peak_welch_t'] is not None else 'nan')},"
                f"{r.get('regime_dominant', '')}"
            )
        for i, r in enumerate(strict):
            csv_lines.append(
                f"{counter},strict_welch,{i},{r['start_cycle']},{r['end_cycle']},{r['duration']},{r['peak_cycle']},"
                f"{r['peak_magnitude']:.6g},{r['peak_cohens_d']:.6g},{r['peak_welch_t']:.6g},"
            )

    json_path.write_text(json.dumps(out, indent=2))
    csv_path.write_text("\n".join(csv_lines) + "\n")
    print(f"  Regions JSON   -> {json_path}")
    print(f"  Regions CSV    -> {csv_path}")


# ──────────────────────────────────────────────────────────────────────────────
# Output: text summary
# ──────────────────────────────────────────────────────────────────────────────

def write_summary_txt(all_results, cycles, n_a, n_b, prefix):
    path = Path(f"{prefix}_summary.txt")
    lines = [
        "CellIFT Per-Cycle Leakage Quantification",
        f"N_A={n_a}  N_B={n_b}  cycles={len(cycles)}",
        "",
    ]

    for counter in COUNTERS:
        if counter not in all_results:
            continue
        m = all_results[counter]["metrics"]
        eps = all_results[counter]["episodes"]
        regime = m["regime"]
        short = COUNTER_SHORT[counter]

        det_count = sum(1 for r in regime if r == DET_LEAK)
        stoch_count = sum(1 for r in regime if r == STOCH_LEAK)
        leaky_idx = [i for i, r in enumerate(regime) if r in (DET_LEAK, STOCH_LEAK)]
        first = int(cycles[leaky_idx[0]]) if leaky_idx else None

        wt = m["welch_t"]
        valid_wt = wt[~np.isnan(wt)]
        max_wt = f"{valid_wt.max():.4f}" if len(valid_wt) else "nan"

        lines += [
            f"[{counter}]",
            f"  first_leaky_cycle   = {first if first is not None else 'none'}",
            f"  total_leaky_cycles  = {det_count + stoch_count}",
            f"  det_leak_cycles     = {det_count}",
            f"  stoch_leak_cycles   = {stoch_count}",
            f"  peak_magnitude      = {m['magnitude'].max():.4f}",
            f"  max_cohens_d        = {m['cohens_d'].max():.4f}",
            f"  max_welch_t         = {max_wt}",
            f"  episodes            = {len(eps)}",
            "",
        ]

        strict = strict_welch_regions(m)
        cyc_episode = _cycles_from_regions(eps)
        cyc_strict = _cycles_from_regions(strict)
        inter = cyc_episode & cyc_strict
        union = cyc_episode | cyc_strict
        jacc = (float(len(inter)) / float(len(union)) if len(union) else 0.0)
        lines += [
            "  [region_overlap]",
            f"    strict_regions    = {len(strict)}",
            f"    strict_cycles     = {len(cyc_strict)}",
            f"    episode_cycles    = {len(cyc_episode)}",
            f"    overlap_cycles    = {len(inter)}",
            f"    overlap_jaccard   = {jacc:.6f}",
            "",
        ]

        if "sign_test" in all_results[counter]:
            s = all_results[counter]["sign_test"]
            lines += [
                "  [sign_test]",
                f"    n_pairs          = {s['n_pairs']}",
                f"    alpha            = {s['alpha']:.6g}",
                f"    alpha_bonf       = {s['alpha_bonferroni']:.6g}",
                f"    significant      = {int(np.sum(s['significant']))}",
                "",
            ]

        if "perm_test" in all_results[counter]:
            p = all_results[counter]["perm_test"]
            lines += [
                "  [perm_test]",
                f"    n_pairs          = {p['n_pairs']}",
                f"    n_permutations   = {p['n_permutations']}",
                f"    min_p_value      = {float(np.nanmin(p['p_value'])):.6g}",
                f"    min_p_value_fdr  = {float(np.nanmin(p['p_value_fdr'])):.6g}",
                "",
            ]

        for i, ep in enumerate(eps):
            wt_str = f"{ep['peak_welch_t']:.4f}" if ep["peak_welch_t"] is not None else "nan"
            lines += [
                f"  [episode_{i}]",
                f"    cycles           = {ep['start_cycle']}-{ep['end_cycle']}",
                f"    duration         = {ep['duration']}",
                f"    regime           = {ep['regime_dominant']}",
                f"    peak_magnitude   = {ep['peak_magnitude']:.4f}",
                f"    peak_cohens_d    = {ep['peak_cohens_d']:.4f}",
                f"    peak_welch_t     = {wt_str}",
                f"    peak_cycle       = {ep['peak_cycle']}",
                "",
            ]

    path.write_text("\n".join(lines))
    print(f"  Summary TXT    -> {path}")


def load_signal_attribution(path):
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        print(f"  WARN: signal attribution JSON not found: {p}")
        return {}
    data = json.loads(p.read_text())
    out = {}
    for cycle_s, rec in data.get("cycles", {}).items():
        try:
            cyc = int(cycle_s)
        except ValueError:
            continue
        out[cyc] = rec.get("top_signal")
    return out


def load_instruction_attribution(path):
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        print(f"  WARN: instruction attribution JSON not found: {p}")
        return {}
    data = json.loads(p.read_text())
    out = {}
    for rec in data.get("cycles", []):
        cyc = rec.get("cycle")
        if isinstance(cyc, int):
            out[cyc] = rec.get("fetch", {})
    return out


def select_intervals_for_annotation(counter_result, top_k=3, threshold_t=4.5):
    """Select interesting intervals by peak |t| (strict first, then episodes as fallback)."""
    strict = []
    for r in strict_welch_regions(counter_result["metrics"], threshold_t=threshold_t):
        row = dict(r)
        row["basis"] = "strict_welch"
        row["regime_dominant"] = "stoch_leak"
        strict.append(row)

    episodes = []
    for r in counter_result["episodes"]:
        row = dict(r)
        row["basis"] = "episode"
        episodes.append(row)

    strict_sorted = sorted(
        strict,
        key=lambda r: (float(r.get("peak_welch_t", float("-inf"))), float(r.get("peak_magnitude", 0.0))),
        reverse=True,
    )
    eps_sorted = sorted(
        episodes,
        key=lambda r: (
            float(r.get("peak_welch_t") if r.get("peak_welch_t") is not None else float("-inf")),
            float(r.get("peak_magnitude", 0.0)),
        ),
        reverse=True,
    )

    selected = []
    seen = set()
    for r in strict_sorted:
        key = (r["start_cycle"], r["end_cycle"], r["basis"])
        if key in seen:
            continue
        selected.append(r)
        seen.add(key)
        if len(selected) >= top_k:
            return selected

    for r in eps_sorted:
        key = (r["start_cycle"], r["end_cycle"], r["basis"])
        if key in seen:
            continue
        selected.append(r)
        seen.add(key)
        if len(selected) >= top_k:
            return selected

    return selected


def plot_annotated_interval(all_results, counter, region, prefix,
                            signal_map, instr_map, margin=20):
    """Plot an interval and annotate with top signal and instruction provenance."""
    if not HAS_MPL:
        return

    m = all_results[counter]["metrics"]
    cycles = m["cycles"]
    start = int(region["start_cycle"])
    end = int(region["end_cycle"])
    win_start = max(int(cycles[0]), start - margin)
    win_end = min(int(cycles[-1]), end + margin)
    mask = (cycles >= win_start) & (cycles <= win_end)

    c_win = cycles[mask]
    mag = m["magnitude"][mask]
    welch = m["welch_t"][mask]

    peak_cycle = int(region["peak_cycle"])
    sig = signal_map.get(peak_cycle)
    ins = instr_map.get(peak_cycle, {})

    sig_text = "n/a"
    if sig:
        sig_name = str(sig.get('signal', 'n/a')).replace("\t", " ")
        sig_text = f"{sig_name} (hw={sig.get('hamming_weight_diff', 'n/a')})"

    instr_text = "n/a"
    src_text = "n/a"
    if ins:
        pc = ins.get("pc")
        instr = ins.get("instruction")
        src = ins.get("source")
        instr_text = f"{pc or 'n/a'}  {instr or 'n/a'}".replace("\t", " ")
        src_text = (src or "n/a").replace("\t", " ")

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13, 7), sharex=True)
    short = COUNTER_SHORT[counter].upper()
    basis = region.get("basis", "episode")
    regime = region.get("regime_dominant", "n/a")

    ax1.plot(c_win, mag, color="steelblue", lw=1.0)
    ax1.fill_between(c_win, mag, color="steelblue", alpha=0.35)
    ax1.axvspan(start, end, color="tomato", alpha=0.12)
    ax1.set_ylabel("Magnitude")
    ax1.grid(alpha=0.2)

    ax2.plot(c_win, welch, color="darkorange", lw=1.0)
    ax2.axhline(4.5, color="red", lw=0.8, ls="--", alpha=0.6)
    ax2.axvspan(start, end, color="tomato", alpha=0.12)
    ax2.set_ylabel("Welch |t|")
    ax2.set_xlabel("Simulation cycle")
    ax2.grid(alpha=0.2)

    title = (
        f"{short} interval {start}-{end} ({basis}, {regime}) | "
        f"peak@{peak_cycle} mag={region.get('peak_magnitude', float('nan')):.1f} "
        f"d={region.get('peak_cohens_d', float('nan')):.1f} "
        f"|t|={region.get('peak_welch_t', float('nan')) if region.get('peak_welch_t') is not None else float('nan'):.2f}"
    )
    fig.suptitle(title, fontsize=10)

    note = (
        f"Signal: {sig_text}\n"
        f"Instr : {instr_text}\n"
        f"Source: {src_text}"
    )
    ax1.text(
        0.01,
        0.98,
        note,
        transform=ax1.transAxes,
        va="top",
        ha="left",
        fontsize=8,
        bbox={"boxstyle": "round", "facecolor": "white", "alpha": 0.8},
    )

    out = f"{prefix}_{COUNTER_SHORT[counter]}_interval_{start}_{end}_annotated.png"
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Interval plot  -> {out}")


# ──────────────────────────────────────────────────────────────────────────────
# Plotting
# ──────────────────────────────────────────────────────────────────────────────

def plot_dashboard(all_results, cycles, prefix, threshold_t=4.5, threshold_d=0.8):
    if not HAS_MPL:
        print("  matplotlib not available — skipping plots")
        return

    # Determine which counters to plot (skip LC if always zero)
    plot_counters = []
    for c in COUNTERS:
        if c in all_results and all_results[c]["metrics"]["magnitude"].max() > 0:
            plot_counters.append(c)
    if not plot_counters:
        plot_counters = [c for c in COUNTERS if c in all_results]

    colors = {
        "hamming_weight_counter_t0": "steelblue",
        "hamming_distance_counter_t0": "darkorange",
        "leakage_counter_t0": "seagreen",
    }

    fig, axes = plt.subplots(4, 1, figsize=(16, 14), sharex=True,
                             gridspec_kw={"height_ratios": [3, 3, 3, 1]})
    fig.suptitle("CellIFT Per-Cycle Leakage Quantification", fontsize=12, y=0.98)

    # Panel 1: Magnitude
    ax = axes[0]
    for c in plot_counters:
        m = all_results[c]["metrics"]
        short = COUNTER_SHORT[c].upper()
        ax.fill_between(cycles, m["magnitude"], alpha=0.4, color=colors[c], label=short)
        ax.plot(cycles, m["magnitude"], lw=0.5, color=colors[c], alpha=0.8)
    ax.set_ylabel("|mean delta_A - mean delta_B|")
    ax.set_title("Per-cycle leakage magnitude")
    ax.legend(fontsize=8, loc="upper right")
    ax.grid(alpha=0.2)
    ax.set_ylim(bottom=0)

    # Panel 2: Cohen's d (log scale for readability)
    ax = axes[1]
    for c in plot_counters:
        m = all_results[c]["metrics"]
        short = COUNTER_SHORT[c].upper()
        d = m["cohens_d"].copy()
        d[d == 0] = np.nan  # hide zero cycles
        ax.plot(cycles, d, lw=0.5, color=colors[c], alpha=0.8, label=short)
        # Mark deterministic cycles with distinct markers (sample to avoid overplotting)
        det_mask = np.array([r == DET_LEAK for r in m["regime"]])
        det_idx = np.where(det_mask)[0]
        if len(det_idx) > 0:
            # Sample at most 200 points for markers
            step = max(1, len(det_idx) // 200)
            sampled = det_idx[::step]
            ax.scatter(cycles[sampled], d[sampled], s=4, color=colors[c],
                       marker="D", alpha=0.5, zorder=5)
    ax.axhline(threshold_d, color="red", lw=0.8, ls="--", alpha=0.6,
               label=f"d={threshold_d} (large)")
    ax.set_ylabel("Cohen's d (effect size)")
    ax.set_title("Per-cycle effect size (diamonds = deterministic divergence)")
    ax.set_yscale("symlog", linthresh=1.0)
    ax.legend(fontsize=8, loc="upper right")
    ax.grid(alpha=0.2)

    # Panel 3: Welch |t|
    ax = axes[2]
    for c in plot_counters:
        m = all_results[c]["metrics"]
        short = COUNTER_SHORT[c].upper()
        ax.plot(cycles, m["welch_t"], lw=0.5, color=colors[c], alpha=0.8, label=short)
    ax.axhline(threshold_t, color="red", lw=0.8, ls="--", alpha=0.6,
               label=f"|t|={threshold_t}")
    ax.set_ylabel("Welch |t|")
    ax.set_title("Per-cycle Welch t-statistic (NaN where variance = 0)")
    ax.legend(fontsize=8, loc="upper right")
    ax.grid(alpha=0.2)

    # Panel 4: Regime strip
    ax = axes[3]
    regime_map = {DET_SAFE: 0, STOCH_SAFE: 1, STOCH_LEAK: 2, DET_LEAK: 3}
    cmap = ListedColormap(["#e8e8e8", "#b0e0b0", "#f5a623", "#e74c3c"])

    strip_data = []
    strip_labels = []
    for c in plot_counters:
        m = all_results[c]["metrics"]
        row = np.array([regime_map.get(r, 0) for r in m["regime"]])
        strip_data.append(row)
        strip_labels.append(COUNTER_SHORT[c].upper())

    strip = np.vstack(strip_data)
    ax.imshow(strip, aspect="auto", cmap=cmap, vmin=0, vmax=3,
              extent=[cycles[0], cycles[-1], len(strip_labels) - 0.5, -0.5],
              interpolation="nearest")
    ax.set_yticks(range(len(strip_labels)))
    ax.set_yticklabels(strip_labels)
    ax.set_xlabel("Simulation cycle")
    ax.set_title("Regime (gray=safe, green=stoch_safe, orange=stoch_leak, red=det_leak)")

    plt.tight_layout()
    out = f"{prefix}_dashboard.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"  Dashboard plot -> {out}")
    plt.close()


def plot_episode_zoom(all_results, cycles, counter, episode, prefix):
    """Zoomed view of a single leakage episode."""
    if not HAS_MPL:
        return

    m = all_results[counter]["metrics"]
    short = COUNTER_SHORT[counter].upper()

    # Expand window by 20% on each side
    start = episode["start_cycle"]
    end = episode["end_cycle"]
    margin = max(10, int((end - start) * 0.2))
    win_start = max(int(cycles[0]), start - margin)
    win_end = min(int(cycles[-1]), end + margin)

    mask = (cycles >= win_start) & (cycles <= win_end)
    c_win = cycles[mask]
    mag_win = m["magnitude"][mask]
    ma_win = m["mean_a"][mask]
    mb_win = m["mean_b"][mask]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 6), sharex=True)
    fig.suptitle(f"Episode: cycles {start}-{end}  [{short}]  "
                 f"(peak mag={episode['peak_magnitude']:.1f} at cy {episode['peak_cycle']})",
                 fontsize=10)

    # Top: overlaid group traces
    ax1.plot(c_win, ma_win, lw=1.0, color="steelblue", label="Group A (delta)")
    ax1.plot(c_win, mb_win, lw=1.0, color="darkorange", label="Group B (delta)")
    ax1.axvspan(start, end, alpha=0.1, color="red", label="Episode")
    ax1.set_ylabel(f"delta({short})")
    ax1.legend(fontsize=8)
    ax1.grid(alpha=0.2)

    # Bottom: magnitude
    ax2.fill_between(c_win, mag_win, alpha=0.5, color="steelblue")
    ax2.plot(c_win, mag_win, lw=0.8, color="steelblue")
    ax2.axvspan(start, end, alpha=0.1, color="red")
    ax2.set_ylabel("|delta_A - delta_B|")
    ax2.set_xlabel("Simulation cycle")
    ax2.grid(alpha=0.2)

    plt.tight_layout()
    out = f"{prefix}_episode_{start}_{end}.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"  Episode zoom   -> {out}")
    plt.close()


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("outdir", help="Directory with group_a_*.csv / group_b_*.csv")
    ap.add_argument("--threshold-t", type=float, default=4.5,
                    help="Welch |t| threshold (default: 4.5)")
    ap.add_argument("--threshold-d", type=float, default=0.8,
                    help="Cohen's d large-effect reference (default: 0.8)")
    ap.add_argument("--min-gap", type=int, default=5,
                    help="Max gap between episodes to merge (default: 5 cycles)")
    ap.add_argument("--plot", action="store_true",
                    help="Generate dashboard + episode zoom PNGs")
    ap.add_argument("--out", default=None,
                    help="Output file prefix (default: OUTDIR/leakage)")
    ap.add_argument("--window", type=int, nargs=2, metavar=("A", "B"),
                    help="Only analyse cycles A..B")
    ap.add_argument("--zoom-top", type=int, default=3,
                    help="Auto-zoom top N episodes per counter (default: 3)")
    ap.add_argument("--plot-intervals", action="store_true",
                    help="Generate Top-K annotated interval plots by peak |t|")
    ap.add_argument("--interval-top-k", type=int, default=3,
                    help="Top-K intervals per counter for annotation (default: 3)")
    ap.add_argument("--interval-margin", type=int, default=20,
                    help="Cycles of context before/after each interval (default: 20)")
    ap.add_argument("--signal-json", default=None,
                    help="Signal attribution JSON from leakage_signals.py --out-json")
    ap.add_argument("--instruction-json", default=None,
                    help="Instruction attribution JSON from pc_at_leakage.py --out-json")
    ap.add_argument("--counter", default="all", choices=["hw", "hd", "lc", "all"],
                    help="Counter to analyse (default: all)")
    ap.add_argument("--paired-sign-test", action="store_true",
                    help="Enable per-cycle paired sign test (Bonferroni-corrected)")
    ap.add_argument("--sign-alpha", type=float, default=0.05,
                    help="Family-wise alpha for sign-test Bonferroni correction (default: 0.05)")
    ap.add_argument("--permutation-test", action="store_true",
                    help="Enable per-cycle paired permutation test (sign-flip null)")
    ap.add_argument("--perm-n-permutations", type=int, default=1000,
                    help="Permutations for paired permutation test (default: 1000)")
    ap.add_argument("--perm-seed", type=int, default=None,
                    help="Optional RNG seed for permutation reproducibility")
    ap.add_argument("--perm-chunk-size", type=int, default=512,
                    help="Cycle chunk size for permutation vectorization (default: 512)")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    if not outdir.is_dir():
        sys.exit(f"ERROR: directory not found: {outdir}")
    prefix = args.out or str(outdir / "leakage")

    print(f"\nLoading TVLA data from {outdir}...")
    traces_a = load_group(outdir, "a")
    traces_b = load_group(outdir, "b")
    traces_a, traces_b, cycles = align_all(traces_a, traces_b)
    print(f"  Aligned: {len(cycles)} cycles, N_A={len(traces_a)}, N_B={len(traces_b)}")

    # Apply window filter
    if args.window:
        w_start, w_end = args.window
        mask = (cycles >= w_start) & (cycles <= w_end)
        cycles = cycles[mask]
        traces_a = [{k: v[mask] if k != "cycle" else cycles for k, v in t.items()}
                    for t in traces_a]
        traces_b = [{k: v[mask] if k != "cycle" else cycles for k, v in t.items()}
                    for t in traces_b]
        # Recompute deltas will be done inside per_cycle_metrics using the windowed data
        # But delta() needs cumulative data, and we've sliced it. We need to handle this.
        # Actually the traces still contain cumulative counter values at the windowed cycles,
        # so delta() on the windowed slice will give correct per-cycle increments within the window.
        print(f"  Window: cycles {w_start}-{w_end} ({len(cycles)} cycles)")

    # Select counters
    if args.counter == "all":
        counters = COUNTERS
    else:
        counters = [COUNTER_FROM_SHORT[args.counter]]

    # Compute metrics
    all_results = {}
    print(f"\nComputing per-cycle metrics...")
    for counter in counters:
        metrics = per_cycle_metrics(
            traces_a, traces_b, counter, cycles,
            threshold_t=args.threshold_t,
        )
        episodes = detect_episodes(metrics, min_gap=args.min_gap)
        all_results[counter] = {"metrics": metrics, "episodes": episodes}

        if args.paired_sign_test:
            all_results[counter]["sign_test"] = paired_sign_test_per_cycle(
                metrics,
                alpha=args.sign_alpha,
            )

        if args.permutation_test:
            print(f"  Permutation test [{COUNTER_SHORT[counter].upper()}]: "
                  f"N={args.perm_n_permutations}, chunk={args.perm_chunk_size}", flush=True)
            all_results[counter]["perm_test"] = paired_permutation_test_per_cycle(
                metrics,
                n_permutations=args.perm_n_permutations,
                seed=args.perm_seed,
                chunk_size=args.perm_chunk_size,
            )

        enrich_episodes_with_det_tests(all_results[counter], cycles)

    # Print report
    print(f"\n{'─' * 70}")
    print(f"  Per-Cycle Leakage Quantification")
    print(f"  N_A={len(traces_a)}  N_B={len(traces_b)}  cycles={len(cycles)}")
    print(f"{'─' * 70}")
    for counter in counters:
        print_counter_report(counter, all_results[counter]["metrics"],
                             all_results[counter]["episodes"])

    # Write outputs
    print(f"\nWriting outputs...")
    write_per_cycle_csv(all_results, cycles, prefix)
    write_episodes_json(all_results, cycles, len(traces_a), len(traces_b), prefix)
    write_summary_txt(all_results, cycles, len(traces_a), len(traces_b), prefix)
    write_regions_outputs(all_results, cycles, prefix, args.threshold_t)

    # Plots
    if args.plot:
        print(f"\nGenerating plots...")
        plot_dashboard(all_results, cycles, prefix,
                       threshold_t=args.threshold_t,
                       threshold_d=args.threshold_d)

        # Episode zooms for top N episodes (by peak magnitude) per counter
        for counter in counters:
            episodes = all_results[counter]["episodes"]
            if not episodes:
                continue
            sorted_eps = sorted(episodes, key=lambda e: e["peak_magnitude"], reverse=True)
            for ep in sorted_eps[:args.zoom_top]:
                plot_episode_zoom(all_results, cycles, counter, ep, prefix)

    if args.plot_intervals:
        print(f"\nGenerating annotated interval plots...")
        signal_map = load_signal_attribution(args.signal_json)
        instr_map = load_instruction_attribution(args.instruction_json)
        for counter in counters:
            selected = select_intervals_for_annotation(
                all_results[counter],
                top_k=args.interval_top_k,
                threshold_t=args.threshold_t,
            )
            for region in selected:
                plot_annotated_interval(
                    all_results,
                    counter,
                    region,
                    prefix,
                    signal_map,
                    instr_map,
                    margin=args.interval_margin,
                )

    print(f"\nAll outputs written with prefix: {prefix}")


if __name__ == "__main__":
    main()
