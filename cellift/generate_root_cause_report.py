#!/usr/bin/env python3
"""
generate_root_cause_report.py - Build a concise root-cause evidence report.

Inputs:
  - run_manifest.json produced by run_full_evaluation.sh
  - leakage_regions.json per group
  - signal/instruction attribution JSON per group

Outputs:
  - root_cause_report.md (human-readable publication-style summary)
  - root_cause_report.json (machine-readable digest)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _load_json(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"Missing JSON file: {path}")
    return json.loads(path.read_text())


def _candidate_regions(counter_info: dict) -> List[dict]:
    strict = list(counter_info.get("strict_welch_regions", []))
    eps = list(counter_info.get("episode_regions", []))

    for r in strict:
        r["basis"] = "strict_welch"
        r.setdefault("regime_dominant", "stoch_leak")
    for r in eps:
        r["basis"] = "episode"
        r.setdefault("regime_dominant", "det_leak")

    ranked = sorted(
        strict,
        key=lambda r: (float(r.get("peak_welch_t", float("-inf"))), float(r.get("peak_magnitude", 0.0))),
        reverse=True,
    )
    if ranked:
        return ranked

    return sorted(
        eps,
        key=lambda r: (
            float(r.get("peak_welch_t") if r.get("peak_welch_t") is not None else float("-inf")),
            float(r.get("peak_magnitude", 0.0)),
        ),
        reverse=True,
    )


def _extract_signal_candidates(rec: dict, limit: int = 3,
                                max_attr_width: int = 4096) -> Tuple[Optional[dict], List[dict]]:
    if not isinstance(rec, dict):
        return None, []
    top_signals = rec.get("top_signals") if isinstance(rec.get("top_signals"), list) else []
    all_cands = [x for x in top_signals if isinstance(x, dict)]
    # Prefer narrow (register/bus) signals over wide (memory array) signals for attribution.
    # Wide memory arrays (e.g. full SRAM) have high raw HW diff but are not individually maskable.
    narrow = [x for x in all_cands if x.get("width", 0) <= max_attr_width]
    cands = (narrow if narrow else all_cands)[:limit]
    # Fall back to original top_signal only if top_signals list was empty
    orig_top = rec.get("top_signal") if isinstance(rec.get("top_signal"), dict) else None
    top = cands[0] if cands else orig_top
    if not cands and orig_top:
        cands = [orig_top]
    return top, cands


def _find_signal_for_interval(signal_json: dict, region: dict,
                               global_fallback_radius: int = 1000) -> Tuple[Optional[dict], Optional[int], List[dict]]:
    cycles = signal_json.get("cycles", {})
    peak = int(region["peak_cycle"])
    s = int(region["start_cycle"])
    e = int(region["end_cycle"])

    rec = cycles.get(str(peak), {})
    top, cands = _extract_signal_candidates(rec)
    if top:
        return top, peak, cands

    # First pass: search within interval bounds.
    nearest = []
    for c_str, rec in cycles.items():
        if not str(c_str).isdigit():
            continue
        c = int(c_str)
        if c < s or c > e:
            continue
        top, cands = _extract_signal_candidates(rec)
        if top:
            nearest.append((abs(c - peak), c, top, cands))

    if nearest:
        nearest.sort(key=lambda x: (x[0], x[1]))
        _, c, top, cands = nearest[0]
        return top, c, cands

    # Second pass: nearest attribution cycle globally (bounded by radius).
    # Useful for masked designs where signal attribution cycles do not overlap
    # with the TVLA-peak interval (e.g., masking hides differences inside the
    # interval but later cycles still carry key-dependent residues).
    global_nearest = []
    for c_str, rec in cycles.items():
        if not str(c_str).isdigit():
            continue
        c = int(c_str)
        dist = abs(c - peak)
        if dist > global_fallback_radius:
            continue
        top, cands = _extract_signal_candidates(rec)
        if top:
            global_nearest.append((dist, c, top, cands))

    if global_nearest:
        global_nearest.sort(key=lambda x: (x[0], x[1]))
        _, c, top, cands = global_nearest[0]
        return top, c, cands

    return None, None, []


def _find_instruction_for_interval(instr_json: dict, region: dict,
                                    fallback_radius: int = 200) -> Tuple[Optional[dict], Optional[int]]:
    rows = instr_json.get("cycles", [])
    by_cycle = {int(r.get("cycle")): r for r in rows if isinstance(r.get("cycle"), int)}

    peak = int(region["peak_cycle"])
    s = int(region["start_cycle"])
    e = int(region["end_cycle"])

    rec = by_cycle.get(peak)
    if rec and rec.get("fetch", {}).get("instruction"):
        return rec.get("fetch"), peak

    for c in range(s, e + 1):
        rec = by_cycle.get(c)
        if rec and rec.get("fetch", {}).get("instruction"):
            return rec.get("fetch"), c

    # Fallback: nearest entry within fallback_radius of peak.
    # Handles single-cycle intervals where the instruction retire lags the TVLA peak.
    nearest = []
    for c, r in by_cycle.items():
        dist = abs(c - peak)
        if dist <= fallback_radius and r.get("fetch", {}).get("instruction"):
            nearest.append((dist, c, r.get("fetch")))
    if nearest:
        nearest.sort(key=lambda x: x[0])
        _, c, fetch = nearest[0]
        return fetch, c

    return None, None


def summarize_group(group_name: str, entry: dict, top_k: int) -> dict:
    regions = _load_json(Path(entry["regions_json"]))
    sig = _load_json(Path(entry["signal_json"]))
    ins = _load_json(Path(entry["instruction_json"]))

    # Optional data-signal JSON (vanilla VCD XOR comparison).
    # Used as fallback when taint-topology attribution returns no matches.
    data_sig_path = entry.get("data_signal_json")
    data_sig: Optional[dict] = None
    masking_candidates: List[dict] = []
    if data_sig_path and Path(data_sig_path).is_file():
        data_sig = _load_json(Path(data_sig_path))
        masking_candidates = (data_sig.get("masking_candidates") or {}).get("signals", [])

    counters = regions.get("counters", {})
    selected = []

    for counter in (
        "leakage_counter_t0",
        "hamming_weight_counter_t0",
        "hamming_distance_counter_t0",
    ):
        cinfo = counters.get(counter)
        if not cinfo:
            continue
        ranked = _candidate_regions(cinfo)[:top_k]
        overlap = cinfo.get("overlap", {})

        for r in ranked:
            s_top, s_cycle, s_candidates = _find_signal_for_interval(sig, r)
            # Fallback to data-signal attribution when taint topology gives no match.
            if s_top is None and data_sig is not None:
                s_top, s_cycle, s_candidates = _find_signal_for_interval(data_sig, r)
            i_top, i_cycle = _find_instruction_for_interval(ins, r)

            selected.append({
                "counter": counter,
                "basis": r.get("basis"),
                "regime": r.get("regime_dominant"),
                "start_cycle": int(r["start_cycle"]),
                "end_cycle": int(r["end_cycle"]),
                "peak_cycle": int(r["peak_cycle"]),
                "peak_magnitude": float(r.get("peak_magnitude", 0.0)),
                "peak_cohens_d": float(r.get("peak_cohens_d", 0.0)),
                "peak_welch_t": r.get("peak_welch_t"),
                "signal_cycle": s_cycle,
                "signal": s_top,
                "signal_candidates": s_candidates,
                "instruction_cycle": i_cycle,
                "instruction": i_top,
                "overlap_jaccard": float(overlap.get("jaccard", 0.0)),
            })

    with_sig = sum(1 for x in selected if x["signal"])
    with_ins = sum(1 for x in selected if x["instruction"])
    with_both = sum(1 for x in selected if x["signal"] and x["instruction"])
    n = len(selected)

    return {
        "group": group_name,
        "first_hw_leak_cycle": int(entry.get("first_hw_leak_cycle", -1)),
        "intervals": selected,
        "attribution_coverage": {
            "intervals": n,
            "with_signal": with_sig,
            "with_instruction": with_ins,
            "with_both": with_both,
            "with_both_ratio": (float(with_both) / float(n) if n else 0.0),
        },
        "masking_candidates": masking_candidates,
    }


def render_markdown(manifest: dict, summary: dict) -> str:
    def clean_cell(text: Optional[str], max_len: int = 140) -> str:
        if text is None:
            return "n/a"
        s = str(text).replace("\t", " ").replace("\n", " ").replace("|", "/")
        s = " ".join(s.split())
        if len(s) > max_len:
            return s[: max_len - 3] + "..."
        return s

    lines = []
    lines.append("# Automated Root-Cause Analysis Report")
    lines.append("")
    lines.append("## Run Configuration")
    lines.append("")
    lines.append(f"- workload: {manifest.get('workload')}")
    lines.append(f"- seed: {manifest.get('seed')}")
    lines.append(f"- simlen: {manifest.get('simlen')}")
    lines.append(f"- threshold_t: {manifest.get('threshold_t')}")
    lines.append(f"- interval_top_k: {manifest.get('interval_top_k')}")
    lines.append("")

    for group_key in ("unmasked", "masked"):
        g = summary.get(group_key)
        if g is None:
            continue
        cov = g["attribution_coverage"]

        def signal_candidates_text(item: dict) -> str:
            cands = item.get("signal_candidates") or []
            if not cands:
                return "n/a"
            rendered = []
            for c in cands:
                name = str(c.get("signal", "n/a")).split(".")[-1]
                hw = c.get("hamming_weight_diff")
                if isinstance(hw, int):
                    rendered.append(f"{name}({hw})")
                else:
                    rendered.append(name)
            return clean_cell(", ".join(rendered), max_len=80)

        lines.append(f"## {group_key.capitalize()} Attribution Summary")
        lines.append("")
        lines.append(f"- first_hw_leak_cycle: {g['first_hw_leak_cycle']}")
        lines.append(f"- intervals analyzed: {cov['intervals']}")
        lines.append(f"- intervals with both signal+instruction: {cov['with_both']} ({cov['with_both_ratio']:.2%})")
        lines.append("")
        lines.append("| Counter | Basis | Regime | Interval | Peak cycle | Peak mag | Peak d | Peak t | Signal | Top signals (HW diff) | Instruction | Source |")
        lines.append("|---|---|---|---|---:|---:|---:|---:|---|---|---|---|")
        for it in g["intervals"]:
            sig = it.get("signal") or {}
            ins = it.get("instruction") or {}
            sig_name = clean_cell(sig.get("signal", "n/a").split(".")[-1] if sig else "n/a", max_len=80)
            sig_cands = signal_candidates_text(it)
            ins_text = clean_cell(ins.get("instruction", "n/a") if ins else "n/a", max_len=80)
            src = clean_cell(ins.get("source", "n/a") if ins else "n/a", max_len=140)
            peak_t = it.get("peak_welch_t")
            peak_t_s = f"{peak_t:.2f}" if isinstance(peak_t, (float, int)) else "n/a"
            lines.append(
                f"| {it['counter']} | {it.get('basis','')} | {it.get('regime','')} | "
                f"{it['start_cycle']}-{it['end_cycle']} | {it['peak_cycle']} | {it['peak_magnitude']:.1f} | "
                f"{it['peak_cohens_d']:.1f} | {peak_t_s} | {sig_name} | {sig_cands} | {ins_text} | {src} |"
            )
        lines.append("")

    # Masking candidates from data-signal attribution (if available).
    # Collect from all groups; deduplicate by signal path, sum HW diff.
    all_candidates: Dict[str, dict] = {}
    for group_key in ("unmasked", "masked"):
        g = summary.get(group_key)
        if g is None:
            continue
        for cand in g.get("masking_candidates") or []:
            sig_path = cand["signal"]
            if sig_path not in all_candidates:
                all_candidates[sig_path] = dict(cand)
            else:
                all_candidates[sig_path]["total_hw_diff"] += cand["total_hw_diff"]
                all_candidates[sig_path]["leaky_interval_count"] = max(
                    all_candidates[sig_path]["leaky_interval_count"],
                    cand["leaky_interval_count"],
                )

    if all_candidates:
        ranked_cands = sorted(all_candidates.values(),
                              key=lambda x: -x["total_hw_diff"])
        lines.append("## Masking Candidates")
        lines.append("")
        lines.append(
            "Signals with the highest key-dependent data divergence across leaky intervals "
            "(from vanilla VCD XOR comparison). These are the primary targets for hardware masking."
        )
        lines.append("")
        lines.append("| Signal | Width | Cumul HW diff | Leaky intervals |")
        lines.append("|---|---:|---:|---:|")
        for cand in ranked_cands[:20]:
            short = cand["signal"].split(".")[-1]
            lines.append(
                f"| {short} | {cand['width']} | {cand['total_hw_diff']} | {cand['leaky_interval_count']} |"
            )
        lines.append("")

    lines.append("## Efficacy Evidence")
    lines.append("")
    lines.append("- Leakage regions are auto-extracted from TVLA outputs using two definitions (episode and strict Welch).")
    lines.append("- Region-level root-cause attribution is automatic and links hardware signals with software instructions.")
    lines.append("- Coverage ratios quantify how often intervals have complete signal+instruction attribution.")
    lines.append("")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifest", help="Path to run_manifest.json")
    ap.add_argument("--top-k", type=int, default=8, help="Top-K intervals per counter/group")
    ap.add_argument("--out-prefix", default=None, help="Output prefix (default: manifest dir/root_cause_report)")
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    manifest = _load_json(manifest_path)

    summary = {
        "unmasked": summarize_group("unmasked", manifest["unmasked"], args.top_k),
        "masked": summarize_group("masked", manifest["masked"], args.top_k) if manifest.get("masked") else None,
    }

    out_prefix = Path(args.out_prefix) if args.out_prefix else (manifest_path.parent / "root_cause_report")
    md_path = Path(str(out_prefix) + ".md")
    json_path = Path(str(out_prefix) + ".json")

    md_path.write_text(render_markdown(manifest, summary))
    json_path.write_text(json.dumps({"manifest": manifest, "summary": summary}, indent=2))

    print(f"Report markdown -> {md_path}")
    print(f"Report json     -> {json_path}")


if __name__ == "__main__":
    main()
