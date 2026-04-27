#!/usr/bin/env python3
"""
Generate publication-style refined summary artifacts.

Inputs:
  - run_manifest_refined.json (or equivalent manifest)
  - root_cause_report_refined.json (or equivalent report digest)

Outputs (from --out-prefix, default: publication_summary_refined):
  - <prefix>.md
  - <prefix>.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Signal classification ─────────────────────────────────────────────────────

_SIGNAL_PATTERNS: List[Tuple[str, str, str]] = [
    # (regex pattern, class_tag, short_description)
    # Patterns are tested in order; put more specific ones first.
    (r"\.mem\[\d+\]$",                   "SRAM_CELL",   "SRAM data word"),
    (r"cache_dbus_cache_\d+_\d+_value",  "DCACHE_WAY",  "D-cache data way"),
    (r"cache_.*_value",                  "CACHE_LINE",  "cache data line"),
    # AXI read data — exact name or embedded in long hierarchical path
    (r"axi_r_payload_data",              "AXI_BUS",     "AXI read data bus"),
    (r"rData_data",                      "AXI_BUS",     "AXI read data bus"),
    (r"AXI.*r.*data|axi.*rdata",         "AXI_BUS",     "AXI read data bus"),
    # OoO-specific: ROB entry PC — control-flow leakage in out-of-order processors
    (r"entries_\d+_pc",                  "ROB_PC",      "ROB entry program counter"),
    # OoO-specific: LSU/Fetcher address registers — address-based leakage
    (r"(Lsu|lsu).*_cmd_address",         "MEM_ADDR",    "LSU memory address register"),
    (r"(Fetcher|fetcher).*_cmd_address", "IFETCH_ADDR", "instruction fetch address"),
    # OoO-specific: Scheduler/ROB state entries
    (r"Scheduler_rob_ssb|Scheduler_RS_EX", "ROB_STATE", "OoO scheduler/ROB state"),
    (r"beats\d+",                        "TL_BEAT",     "TileLink beat data"),
    # TileLink broadcast/tracker data — Rocket TLBroadcastTracker
    (r"TLBroadcast.*data",               "TL_BEAT",     "TileLink broadcast data"),
    # SRAM array data — Rocket ram[N], ram_data[N]
    (r"ram_data\[",                      "SRAM_CELL",   "SRAM data output register"),
    (r"\bram\[\d+\]",                    "SRAM_CELL",   "SRAM data word"),
    # Register file — array-indexed or named aggregate (with optional taint suffix)
    (r"rf\[\d+\]",                       "REG_FILE",    "integer register file"),
    (r"rf_reg",                          "REG_FILE",    "integer register file"),
    # Multiplier/MAC — Ibex mac_res, multdiv_result; Rocket mulReg/nextMulReg
    (r"mac_res",                         "MULT_REG",    "hardware MAC/multiplier result"),
    (r"multdiv_result",                  "MULT_REG",    "hardware multiply-divide result"),
    (r"nextMulReg|mulReg|unrolls_\d+",   "MULT_REG",    "hardware multiplier register"),
    (r"alu[_\.]?(out|in|io_)",           "ALU_OUT",     "ALU result"),
    (r"rdata_o",                         "MEM_RDATA",   "memory read data output"),
    (r"ex_reg_rs",                       "EX_REG",      "execute-stage register source"),
    (r"id_rs_\d+",                       "DECODE_REG",  "decode-stage register source"),
    # FIFO read data — Ibex rspfifo_rdata_leak0, generic fifo_rdata
    (r"rspfifo_rdata",                   "FIFO_DATA",   "response FIFO read data"),
    (r"fifo.*rdata",                     "FIFO_DATA",   "FIFO read data"),
    (r"icData_data",                     "ICACHE_DATA", "instruction cache data"),
]


def classify_signal(full_path: str) -> Tuple[str, str]:
    """Return (class_tag, short_description) for an RTL signal path."""
    for pattern, tag, desc in _SIGNAL_PATTERNS:
        if re.search(pattern, full_path):
            return tag, desc
    return "DATAPATH", "datapath signal"


# ── Crypto function annotation database ──────────────────────────────────────
# Covers both Kyber-512 and AES-128 workloads.
# Matched by substring against the function name extracted from addr2line output.

_CRYPTO_FUNCTIONS: Dict[str, Dict[str, str]] = {
    # ── Kyber-512 ─────────────────────────────────────────────────────────────
    "poly_frombytes": {
        "role": "KEY_LOAD",
        "data_sensitivity": "SECRET",
        "why_leaks": (
            "The secret polynomial coefficients are packed as raw bytes in SRAM and loaded "
            "without masking; each SRAM read exposes key-dependent Hamming weight."
        ),
    },
    "poly_tobytes": {
        "role": "KEY_PACK",
        "data_sensitivity": "SECRET",
        "why_leaks": (
            "Unmasked secret coefficients are written back to memory byte-by-byte."
        ),
    },
    "fqmul": {
        "role": "NTT_MULT",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "Montgomery multiplication of a secret NTT coefficient; intermediate partial "
            "products in the multiplier pipeline carry key-dependent values with no arithmetic masking."
        ),
    },
    "basemul": {
        "role": "NTT_MULT",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "Point-wise multiplication of the secret polynomial with a public polynomial in "
            "the NTT domain; result coefficients are key-dependent with no masking."
        ),
    },
    "KeccakF1600_StatePermute": {
        "role": "SEED_EXPAND",
        "data_sensitivity": "SEED_DERIVED",
        "why_leaks": (
            "During key generation, the Keccak state at this point is derived from the secret "
            "seed; the XOR operation exposes state bits correlated with the key."
        ),
    },
    "montgomery_reduce": {
        "role": "NTT_REDUCE",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "Modular reduction of key-dependent NTT intermediate values without arithmetic masking."
        ),
    },
    "ntt": {
        "role": "NTT_TRANSFORM",
        "data_sensitivity": "SECRET",
        "why_leaks": "Direct NTT transform on secret polynomial coefficients.",
    },
    "invntt": {
        "role": "NTT_TRANSFORM",
        "data_sensitivity": "SECRET",
        "why_leaks": "Inverse NTT transform on secret polynomial coefficients.",
    },

    # ── AES-128 ───────────────────────────────────────────────────────────────
    "AES_encrypt": {
        "role": "AES_ROUND",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "AES encryption mixes the secret key with plaintext through ten rounds of "
            "SubBytes, ShiftRows, MixColumns, and AddRoundKey; every intermediate state "
            "is key-dependent and unmasked."
        ),
    },
    "AES_decrypt": {
        "role": "AES_ROUND",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "AES decryption applies the inverse cipher using the secret round keys; "
            "all intermediate states are key-dependent and unmasked."
        ),
    },
    "SubBytes": {
        "role": "AES_SBOX",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "The AES S-box substitution is a non-linear key-dependent operation; "
            "the output directly depends on the secret key XORed with the plaintext "
            "at the first round — the classic first-order DPA target."
        ),
    },
    "AddRoundKey": {
        "role": "AES_ROUND",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "AddRoundKey XORs the AES state with the round key derived from the secret; "
            "the output is directly correlated with both the key and the plaintext."
        ),
    },
    "MixColumns": {
        "role": "AES_ROUND",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "MixColumns multiplies each column of the AES state over GF(2⁸); "
            "the result propagates key-dependent values across bytes without masking."
        ),
    },
    "KeyExpansion": {
        "role": "KEY_SCHEDULE",
        "data_sensitivity": "SECRET",
        "why_leaks": (
            "The AES key schedule derives all round keys from the raw secret key; "
            "round key words computed and stored in SRAM directly expose the secret."
        ),
    },
    "KeyExpansionCore": {
        "role": "KEY_SCHEDULE",
        "data_sensitivity": "SECRET",
        "why_leaks": (
            "The core key schedule operation (RotWord + SubWord + Rcon XOR) directly "
            "processes raw secret key bytes, making each computation key-dependent."
        ),
    },
    "xtime": {
        "role": "AES_FIELD_MULT",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "GF(2⁸) multiplication by 2 used in MixColumns; operand is key-dependent "
            "state so the result and conditional reduction carry secret information."
        ),
    },
    # AES snake_case aliases (implementations using lowercase function names)
    "gf_mul2": {
        "role": "AES_FIELD_MULT",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "GF(2⁸) multiplication by 2 (also known as xtime) used in MixColumns; "
            "the operand is key-dependent AES state, so the result and conditional "
            "reduction carry secret information."
        ),
    },
    "mix_columns": {
        "role": "AES_ROUND",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "MixColumns multiplies each column of the AES state over GF(2⁸); "
            "the result propagates key-dependent values across bytes without masking."
        ),
    },
    "shift_rows": {
        "role": "AES_ROUND",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "ShiftRows cyclically shifts the AES state rows; the data values are "
            "key-dependent and their Hamming weight leaks the secret."
        ),
    },
    "sub_bytes": {
        "role": "AES_SBOX",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "SubBytes applies the AES S-box to each state byte; the output at the first "
            "round is directly predictable from plaintext and key — the classic DPA target."
        ),
    },
    "add_round_key": {
        "role": "AES_ROUND",
        "data_sensitivity": "SECRET_DERIVED",
        "why_leaks": (
            "AddRoundKey XORs the AES state with the round key; the output is "
            "directly correlated with both key and plaintext."
        ),
    },
    # Masked AES gadgets (common naming conventions)
    "mask_refresh": {
        "role": "MASK_REFRESH",
        "data_sensitivity": "MASK",
        "why_leaks": (
            "Mask refresh generates fresh randomness; leakage here indicates that the "
            "mask update itself is not perfectly uniform or has higher-order correlations."
        ),
    },
    "DOM_and": {
        "role": "MASKED_GATE",
        "data_sensitivity": "MASKED",
        "why_leaks": (
            "Domain-oriented masking AND gate; leakage indicates a higher-order "
            "vulnerability in the masked implementation, e.g. from glitches or "
            "insufficient re-masking between shares."
        ),
    },
    "sbox_masked": {
        "role": "AES_SBOX",
        "data_sensitivity": "MASKED",
        "why_leaks": (
            "Masked S-box substitution; leakage here indicates the masking scheme does "
            "not achieve first-order security, likely due to share recombination or "
            "glitch propagation."
        ),
    },
}

_FALLBACK_FUNC = {
    "role": "UNKNOWN",
    "data_sensitivity": "UNKNOWN",
    "why_leaks": "Key-dependent data detected at this function.",
}


# ── Narrative template matrix ─────────────────────────────────────────────────

_NARRATIVE_TEMPLATES: Dict[Tuple[str, str], str] = {
    ("SRAM_CELL", "KEY_LOAD"): (
        "SRAM words hold packed secret coefficient bytes; directly expose key-dependent "
        "Hamming weight on every read. Expected in any unmasked implementation."
    ),
    ("SRAM_CELL", "KEY_PACK"): (
        "SRAM words receive unmasked secret coefficients packed byte-by-byte. "
        "Expected in any unmasked implementation."
    ),
    ("SRAM_CELL", "SEED_EXPAND"): (
        "SRAM holds Keccak state derived from the key seed at this permutation point; "
        "XOR operation is key-correlated."
    ),
    ("SRAM_CELL", "NTT_MULT"): (
        "SRAM holds secret NTT coefficient values during polynomial multiplication; "
        "each read exposes key-dependent Hamming weight."
    ),
    ("DCACHE_WAY", "NTT_MULT"): (
        "128-bit D-cache line holds multiple secret NTT coefficients simultaneously. "
        "In an unmasked design, all coefficient bits appear on the cache data bus during "
        "polynomial multiplication."
    ),
    ("DCACHE_WAY", "KEY_LOAD"): (
        "D-cache line carries packed secret polynomial bytes during key loading. "
        "Expected in any cached unmasked design."
    ),
    ("AXI_BUS", "NTT_MULT"): (
        "Secret NTT coefficients transferred over the AXI data bus from SRAM to cache. "
        "MASKING-BOUNDARY LEAK: even in a design with masked arithmetic, an unprotected "
        "AXI bus exposes key shares during memory transfers."
    ),
    ("AXI_BUS", "KEY_LOAD"): (
        "Secret polynomial bytes transferred over the AXI data bus during key loading. "
        "MASKING-BOUNDARY LEAK: key shares exposed at the memory interface regardless "
        "of arithmetic masking."
    ),
    ("TL_BEAT", "NTT_MULT"): (
        "TileLink beat data carries key-dependent NTT coefficients across the on-chip "
        "interconnect. MASKING-BOUNDARY INDICATOR: this bus would expose key shares if "
        "arithmetic masking is applied but the memory interface is not protected."
    ),
    ("TL_BEAT", "KEY_LOAD"): (
        "TileLink beat data carries secret polynomial bytes across the interconnect. "
        "MASKING-BOUNDARY INDICATOR: unprotected bus exposes key shares at transfer time."
    ),
    ("MULT_REG", "NTT_MULT"): (
        "Hardware multiplier intermediate register carries the partial product of a secret "
        "NTT coefficient. In an unmasked design, every pipeline stage of the multiplier "
        "exposes key-dependent bits."
    ),
    ("MULT_REG", "NTT_REDUCE"): (
        "Hardware multiplier register holds intermediate values during Montgomery reduction "
        "of key-dependent NTT coefficients."
    ),
    ("MEM_RDATA", "KEY_LOAD"): (
        "SRAM output bus carries unmasked secret coefficient bytes before entering "
        "the register file."
    ),
    ("REG_FILE", "NTT_MULT"): (
        "Integer register file holds secret NTT coefficient values during polynomial "
        "multiplication. Expected when no register-file masking is applied."
    ),
    # ── AES templates ─────────────────────────────────────────────────────────
    ("SRAM_CELL", "AES_ROUND"): (
        "SRAM word holds AES round state (cipher state bytes or round key words); "
        "each memory access exposes the key-dependent intermediate value directly. "
        "Expected in any software AES without memory masking."
    ),
    ("SRAM_CELL", "KEY_SCHEDULE"): (
        "SRAM holds raw AES key bytes or derived round keys during key expansion; "
        "every store/load directly exposes secret key material. "
        "Primary first-order DPA target in unmasked software AES."
    ),
    ("SRAM_CELL", "AES_SBOX"): (
        "SRAM holds the AES S-box lookup table or state bytes around the substitution step; "
        "the access pattern and data value are both key-dependent."
    ),
    ("SRAM_CELL", "AES_FIELD_MULT"): (
        "SRAM holds AES state bytes during GF(2⁸) field multiplication in MixColumns; "
        "the operand is key-dependent and its Hamming weight leaks the secret."
    ),
    ("REG_FILE", "AES_ROUND"): (
        "Integer register file holds AES round state words; every instruction that "
        "processes a register value exposes the key-dependent Hamming weight or distance. "
        "Expected in unmasked software AES executing rounds in registers."
    ),
    ("REG_FILE", "AES_SBOX"): (
        "Register file holds the AES state byte before/after S-box substitution — "
        "the classic first-order DPA target. The S-box output XORed with the round key "
        "is directly predictable from plaintext and key hypothesis."
    ),
    ("REG_FILE", "KEY_SCHEDULE"): (
        "Register file holds round key words during AES key expansion; "
        "each register write exposes raw key-derived data."
    ),
    ("ALU_OUT", "AES_ROUND"): (
        "ALU result carries the output of an AddRoundKey XOR or S-box-derived computation; "
        "the result is key-dependent and its Hamming weight is directly exploitable."
    ),
    ("ALU_OUT", "AES_SBOX"): (
        "ALU computes the S-box output or the first-round XOR of plaintext with round key; "
        "the classic DPA target — result is correlated with the secret key byte."
    ),
    ("DCACHE_WAY", "AES_ROUND"): (
        "D-cache line holds multiple AES state bytes simultaneously; "
        "cache line Hamming weight leaks several key-dependent bytes at once, "
        "enabling multi-byte DPA attacks."
    ),
    ("DCACHE_WAY", "AES_SBOX"): (
        "D-cache line holds S-box lookup table entries or AES state around SubBytes; "
        "the access addresses and data values are both key-dependent."
    ),
    ("AXI_BUS", "AES_ROUND"): (
        "AES round state transferred over the AXI data bus. "
        "MASKING-BOUNDARY LEAK: even in a design with masked AES computation, "
        "an unprotected AXI bus transfers unmasked state during memory load/store."
    ),
    ("TL_BEAT", "AES_ROUND"): (
        "AES round state or round key words carried over the TileLink interconnect. "
        "MASKING-BOUNDARY INDICATOR: arithmetic masking of the AES computation alone "
        "does not protect data on the memory bus."
    ),
    ("TL_BEAT", "KEY_SCHEDULE"): (
        "AES round key words transferred over TileLink during key schedule SRAM writes. "
        "MASKING-BOUNDARY INDICATOR: raw key material visible on the bus regardless of "
        "any arithmetic masking applied to the cipher computation."
    ),
    ("MULT_REG", "AES_FIELD_MULT"): (
        "Hardware multiplier holds GF(2⁸) operands during AES MixColumns field multiplication; "
        "the operands are key-dependent AES state bytes."
    ),
    # ROB_PC — OoO processor ROB entry program counters (control-flow leakage)
    ("ROB_PC", "AES_ROUND"): (
        "ROB entry program counters are key-dependent because the AES implementation "
        "contains data-dependent branches (e.g., loop bounds or conditional stores "
        "that depend on computed AES state). The branch outcome varies between key "
        "hypotheses, making in-flight PC values in the ROB observable via TVLA. "
        "This is a control-flow side channel specific to out-of-order processors."
    ),
    ("ROB_PC", "AES_SBOX"): (
        "ROB entry PCs are correlated with the secret key due to data-dependent "
        "branching during S-box table accesses; the fetch sequence itself leaks "
        "the key-dependent memory access pattern."
    ),
    ("ROB_PC", "KEY_SCHEDULE"): (
        "ROB entry PCs during key expansion are key-dependent; the key schedule "
        "branches on computed round-key bytes, making the in-flight instruction "
        "stream observable via TVLA."
    ),
    # MEM_ADDR — LSU address register leaks key-dependent table access index
    ("MEM_ADDR", "AES_SBOX"): (
        "The LSU holds the S-box table lookup address, which is a direct function "
        "of key XOR plaintext — the classic address-based DPA target. The address "
        "itself (not just the loaded data) leaks the secret through power variation. "
        "Exploitable with address-based profiling even in the presence of data masking."
    ),
    ("MEM_ADDR", "AES_ROUND"): (
        "The LSU memory address register holds a key-dependent AES state address; "
        "the address bit-pattern correlates with the secret key through the computed "
        "array index."
    ),
    ("MEM_ADDR", "KEY_SCHEDULE"): (
        "The LSU address register holds the round-key store address during key expansion; "
        "the computed address is key-dependent."
    ),
    # ROB_STATE — scheduler/ROB state leaking OoO execution status
    ("ROB_STATE", "AES_ROUND"): (
        "Out-of-order scheduler/ROB state (reservation station entries, predictor entries) "
        "is correlated with the AES computation because instruction issue order, "
        "execution unit allocation, and predictor updates depend on key-dependent "
        "branch outcomes and memory access patterns."
    ),
    # FIFO_DATA — Ibex response FIFO carrying memory load results
    ("FIFO_DATA", "AES_SBOX"): (
        "The response FIFO carries the S-box lookup result loaded from SRAM. "
        "Even in a masked implementation, if the table is accessed by a key-dependent "
        "index, the FIFO data value (or its Hamming weight) reveals the secret — "
        "a cache/SRAM table-based S-box vulnerability."
    ),
    ("FIFO_DATA", "AES_ROUND"): (
        "The response FIFO carries AES state bytes loaded from SRAM; "
        "each load of a key-dependent state word exposes the Hamming weight on the FIFO bus."
    ),
    ("FIFO_DATA", "KEY_SCHEDULE"): (
        "The response FIFO carries round key words loaded from SRAM during key expansion; "
        "raw key material is visible on the memory response bus."
    ),
    # MULT_REG — multiplier/MAC in AES field operations
    ("MULT_REG", "AES_FIELD_MULT"): (
        "The hardware MAC/multiplier holds an intermediate GF(2⁸) operand during MixColumns; "
        "the key-dependent AES state byte appears in the multiplier pipeline."
    ),
    ("MULT_REG", "AES_ROUND"): (
        "The hardware multiplier register holds a key-dependent AES state word; "
        "the Hamming weight of the result leaks at each clock cycle."
    ),
    # REG_FILE + AES round (general case)
    ("REG_FILE", "AES_ROUND"): (
        "Integer register file holds AES round state words; every instruction that "
        "reads or writes a register exposes the key-dependent Hamming weight or distance."
    ),
    # Masked AES — residual leakage patterns
    ("SRAM_CELL", "MASK_REFRESH"): (
        "SRAM holds mask shares during refresh; leakage indicates the refresh randomness "
        "is correlated with protected data, breaking the masking security."
    ),
    ("SRAM_CELL", "MASKED_GATE"): (
        "SRAM holds masked share values; leakage from a masked AND gate stored in memory "
        "indicates a higher-order vulnerability (share recombination or glitch)."
    ),
    ("REG_FILE", "MASKED_GATE"): (
        "Register file holds masked shares during a DOM AND operation; "
        "higher-order leakage indicates share recombination within the same register file "
        "read port, a known vulnerability of register-file-based masked software."
    ),
}

_MASKING_BOUNDARY_CLASSES = {"AXI_BUS", "TL_BEAT"}


def _func_annotation(func_name: str) -> Dict[str, str]:
    """Return crypto function annotation, matching by case-insensitive substring."""
    fn_lower = func_name.lower()
    for key, ann in _CRYPTO_FUNCTIONS.items():
        if key.lower() in fn_lower:
            return ann
    return _FALLBACK_FUNC


def generate_leakage_narrative(group_data: dict, group_name: str) -> List[str]:
    """Generate markdown lines for the ## Leakage Narrative subsection."""
    intervals = group_data.get("intervals", [])
    if not intervals:
        return []

    # Collect (signal_class, func_role, signal_path, func_name) per interval
    classified = []
    for item in intervals:
        sig = item.get("signal") or {}
        full_path = sig.get("signal", "")
        s_class, _ = classify_signal(full_path) if full_path else ("UNKNOWN", "")

        src = (item.get("instruction") or {}).get("source", "")
        func_name = "n/a"
        if src:
            tokens = re.split(r"  +", src.strip())
            for tok in tokens:
                tok = tok.split(" ")[0]
                if "/" not in tok and tok.count(":") != 1 and tok and tok != "??":
                    func_name = tok
                    break

        ann = _func_annotation(func_name)
        classified.append({
            "signal_class": s_class,
            "func_name": func_name,
            "func_role": ann["role"],
            "data_sensitivity": ann["data_sensitivity"],
            "why_leaks": ann["why_leaks"],
            "full_path": full_path,
            "is_boundary": s_class in _MASKING_BOUNDARY_CLASSES,
        })

    total = len(classified)

    # Dominant pattern
    from collections import Counter
    pattern_counts: Counter = Counter(
        (c["signal_class"], c["func_role"]) for c in classified
        if c["signal_class"] != "UNKNOWN" and c["func_role"] != "UNKNOWN"
    )
    dominant = pattern_counts.most_common(1)

    # Masking-boundary signals
    boundary_items = [c for c in classified if c["is_boundary"]]
    boundary_count = len(boundary_items)

    lines: List[str] = []
    lines.append(f"### {group_name.capitalize()} Design")
    lines.append("")

    if dominant:
        (dom_class, dom_role), dom_count = dominant[0]
        lines.append(f"**Dominant pattern**: {dom_class} during {dom_role} ({dom_count}/{total} intervals)")
        lines.append("")

        template = _NARRATIVE_TEMPLATES.get(
            (dom_class, dom_role),
            _CRYPTO_FUNCTIONS.get(dom_role, _FALLBACK_FUNC).get("why_leaks",
                "Key-dependent data detected at this function.")
        )

        # Collect unique function names for this dominant pattern
        dom_funcs = sorted({
            c["func_name"] for c in classified
            if c["signal_class"] == dom_class and c["func_role"] == dom_role
            and c["func_name"] not in ("n/a", "??", "UNKNOWN")
        })
        # Collect example signal names (up to 3)
        dom_sigs = []
        seen_sigs: set = set()
        for c in classified:
            leaf = c["full_path"].split(".")[-1] if c["full_path"] else ""
            if c["signal_class"] == dom_class and leaf and leaf not in seen_sigs:
                dom_sigs.append(leaf)
                seen_sigs.add(leaf)
            if len(dom_sigs) >= 3:
                break

        func_str = (
            f"`{'`, `'.join(dom_funcs)}`" if dom_funcs else "the identified function"
        )
        sig_str = (
            f" (e.g. `{'`, `'.join(dom_sigs)}`)" if dom_sigs else ""
        )

        lines.append(
            f"The primary leakage occurs during {func_str}. "
            f"The {dom_class} signals{sig_str} are the main attribution target. "
            f"{template}"
        )
        lines.append("")
    else:
        lines.append("*No dominant leakage pattern identified (insufficient attribution data).*")
        lines.append("")

    if boundary_count > 0:
        boundary_classes = sorted({c["signal_class"] for c in boundary_items})
        boundary_sig_names = sorted({
            c["full_path"].split(".")[-1]
            for c in boundary_items if c["full_path"]
        })
        sig_list = ", ".join(f"`{s}`" for s in boundary_sig_names[:3])
        lines.append(
            f"**Masking-boundary signals**: {sig_list} detected in "
            f"{boundary_count}/{total} intervals "
            f"({', '.join(boundary_classes)}). "
            "Even in a design with masked arithmetic computation, an unprotected memory "
            "bus would expose key shares during key-loading transfers — a key-loading "
            "vulnerability that masking the datapath alone does not eliminate."
        )
        lines.append("")
    else:
        lines.append(
            "**Masking-boundary signals**: none detected "
            "(leakage is confined to datapath/memory, not bus-level)."
        )
        lines.append("")

    # Remediation hint based on dominant (signal_class, func_role)
    dom_class = dominant[0][0][0] if dominant else ""
    dom_role  = dominant[0][0][1] if dominant else ""
    _remediation_by_role: Dict[str, str] = {
        "AES_ROUND": (
            "Apply first-order Boolean masking to the AES state; split each state byte into "
            "two shares (e.g. using DOM or ISW) before SubBytes, MixColumns, and AddRoundKey. "
            "Ensure shares are never recombined in the same clock cycle."
        ),
        "AES_SBOX": (
            "Mask the AES S-box input and output using a table-based masked S-box or a "
            "bitsliced DOM implementation; the unmasked S-box output is the primary DPA target."
        ),
        "KEY_SCHEDULE": (
            "Mask the AES key schedule: derive and store round keys in masked form, "
            "never writing unmasked round key bytes to SRAM."
        ),
        "AES_FIELD_MULT": (
            "Apply arithmetic masking to the GF(2⁸) multiplication operands in MixColumns; "
            "use a masked field multiplication gadget."
        ),
        "MASKED_GATE": (
            "Investigate share recombination in the masked AND gadget; ensure independent "
            "randomness is consumed per gate and shares are not combined within the same "
            "register file read port or pipeline stage."
        ),
    }
    _remediation_by_class: Dict[str, str] = {
        "ROB_PC": (
            "Eliminate data-dependent branches from the AES implementation (constant-time "
            "coding); replace table-based S-box with a bitsliced implementation to remove "
            "key-dependent memory addresses and branch targets from the instruction stream."
        ),
        "MEM_ADDR": (
            "Use a bitsliced or arithmetic-masked S-box that does not perform key-dependent "
            "table lookups; the lookup address itself is exploitable even if the loaded "
            "data is masked."
        ),
        "ROB_STATE": (
            "Eliminate data-dependent branches and memory access patterns from the AES "
            "implementation; OoO processor state is correlated with the execution path "
            "even after the instruction retires."
        ),
        "FIFO_DATA": (
            "Mask the data on the memory response bus before it enters the datapath; "
            "if using a table-based S-box, replace it with a bitsliced or arithmetic "
            "masked implementation that does not expose the output on the load data bus."
        ),
        "SRAM_CELL": (
            "Apply Boolean masking at the SRAM interface; split secret values into shares "
            "before storing to memory and recombine only in a protected context."
        ),
        "DCACHE_WAY": (
            "Mask secret values before cache writes, or use a cache-bypass load path "
            "for key material to avoid exposing full cache lines."
        ),
        "AXI_BUS": (
            "Protect the AXI data bus with bus-level masking or ensure all secret values "
            "are split into shares before they are placed on the memory interconnect."
        ),
        "TL_BEAT": (
            "Protect the TileLink data bus or ensure key shares are split before transfer; "
            "arithmetic masking of computation alone is insufficient."
        ),
        "MULT_REG": (
            "Apply arithmetic masking to multiplier inputs and outputs; "
            "split operands into shares before entering the MulDiv unit."
        ),
        "REG_FILE": (
            "Apply register-file masking; store secret values as share pairs and ensure "
            "both shares are never in the same register file read port simultaneously."
        ),
        "ALU_OUT": (
            "Apply Boolean masking to the ALU datapath; the key-dependent XOR result "
            "must be split into shares before the ALU output stage."
        ),
    }
    # For structural/control-flow leakage classes, class-level remediation is
    # more accurate than the generic role-level masking advice.
    _STRUCTURAL_CLASSES = {"ROB_PC", "MEM_ADDR", "ROB_STATE", "IFETCH_ADDR"}
    if dom_class in _STRUCTURAL_CLASSES:
        remediation = (
            _remediation_by_class.get(dom_class)
            or _remediation_by_role.get(dom_role)
            or "Apply appropriate masking at the identified leakage point."
        )
    else:
        remediation = (
            _remediation_by_role.get(dom_role)
            or _remediation_by_class.get(dom_class)
            or "Apply appropriate masking at the identified leakage point."
        )

    lines.append(f"**Remediation**: {remediation}")
    lines.append("")

    return lines


def load_json(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"Missing JSON file: {path}")
    return json.loads(path.read_text())


_COUNTERS = [
    "leakage_counter_t0",
    "hamming_weight_counter_t0",
    "hamming_distance_counter_t0",
]


def parse_tvla_summary(summary_path: Path) -> dict:
    """Parse welch_summary.txt.

    Returns a dict with keys:
      welch_applicable : bool  — True if Welch t-test was computed
      max_t            : dict  — counter → float (0.0 if not available)
      max_diff         : dict  — counter → int   (between-group, always available)
    """
    res: dict = {
        "welch_applicable": False,
        "max_t":    {c: 0.0 for c in _COUNTERS},
        "max_diff": {c: 0   for c in _COUNTERS},
    }
    if not summary_path.is_file():
        return res

    section: Optional[str] = None  # "between" | "welch"
    current: Optional[str] = None

    for raw in summary_path.read_text().splitlines():
        line = raw.strip()

        if "# Between-group comparison" in line:
            section, current = "between", None
            continue
        if line.startswith("# Welch t-test results"):
            res["welch_applicable"] = True
            section, current = "welch", None
            continue
        if line.startswith("# Welch t-test:") and "not applicable" in line:
            res["welch_applicable"] = False
            section = None
            continue
        if section is None:
            continue

        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            continue
        if current not in _COUNTERS:
            continue

        if section == "between" and line.startswith("max_diff"):
            try:
                res["max_diff"][current] = int(line.split("=", 1)[1].strip())
            except (IndexError, ValueError):
                pass

        if section == "welch" and line.startswith("max_t"):
            try:
                res["max_t"][current] = float(line.split("=", 1)[1].strip())
            except (IndexError, ValueError):
                pass

    return res


def parse_welch_maxima(summary_path: Path) -> Dict[str, float]:
    """Backward-compat wrapper — returns max_t (or max_diff when Welch n/a)."""
    info = parse_tvla_summary(summary_path)
    if info["welch_applicable"]:
        return info["max_t"]
    # Welch not applicable: promote max_diff so downstream callers get a
    # non-zero signal rather than misleading zeros.
    return {c: float(info["max_diff"][c]) for c in _COUNTERS}


def short_signal_name(item: dict) -> str:
    signal = item.get("signal") or {}
    full = signal.get("signal")
    if not full:
        return "n/a"
    return str(full).split(".")[-1]


def short_instruction(item: dict) -> str:
    instr = item.get("instruction") or {}
    txt = instr.get("instruction")
    if not txt:
        return "n/a"
    return " ".join(str(txt).split())


def short_source(item: dict) -> str:
    src = (item.get("instruction") or {}).get("source")
    if not src:
        return "n/a"
    # Split on 2+ spaces to tokenize interleaved func names + file paths.
    # Format: "funcA  /path/file.c:line  funcB  /path/file.c:line  ..."
    # We want only the first (func, file:line) pair.
    tokens = re.split(r"  +", src.strip())
    func, fileline = "n/a", "n/a"
    for tok in tokens:
        tok = tok.split(" ")[0]  # drop "(discriminator N)" suffixes
        if "/" in tok or (tok.count(":") == 1 and not tok.startswith("-")):
            # file:line token — take basename:line
            fileline = os.path.basename(tok)
            break  # stop after the first complete (func, fileline) pair
        elif tok and func == "n/a":
            # first non-path token is function name; strip long namespace prefix
            fname = tok.split("_ref_")[-1] if "_ref_" in tok else tok
            func = fname
    return f"{func} ({fileline})" if fileline != "n/a" else func


def collect_table_rows(report: dict) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    summary = report.get("summary", {})

    for group in ("unmasked", "masked"):
        group_data = summary.get(group) or {}
        for item in group_data.get("intervals", []):
            peak_t = item.get("peak_welch_t")
            rows.append(
                {
                    "group": group,
                    "counter": item.get("counter", "n/a"),
                    "interval": f"{item.get('start_cycle', 'n/a')}-{item.get('end_cycle', 'n/a')}",
                    "peak_cycle": item.get("peak_cycle", "n/a"),
                    "peak_t": float(peak_t) if isinstance(peak_t, (int, float)) else "n/a",
                    "signal": short_signal_name(item),
                    "instruction": short_instruction(item),
                    "source": short_source(item),
                }
            )

    return rows


def coverage_text(report: dict, group: str) -> Tuple[int, int]:
    group_data = report.get("summary", {}).get(group) or {}
    cov = group_data.get("attribution_coverage", {})
    return int(cov.get("with_both", 0)), int(cov.get("intervals", 0))


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["group", "counter", "interval", "peak_cycle", "peak_t", "signal", "instruction", "source"])
        for row in rows:
            peak_t = row["peak_t"]
            peak_t_str = f"{peak_t:.4f}" if isinstance(peak_t, (int, float)) else "n/a"
            writer.writerow([
                row["group"],
                row["counter"],
                row["interval"],
                row["peak_cycle"],
                peak_t_str,
                row["signal"],
                row["instruction"],
                row.get("source", "n/a"),
            ])


def write_md(path: Path, report: dict, rows: List[Dict[str, object]], csv_name: str,
             report_path: Optional[Path] = None) -> None:
    manifest = report.get("manifest", {})
    unmasked_first = report.get("summary", {}).get("unmasked", {}).get("first_hw_leak_cycle", "n/a")
    masked_first = (report.get("summary", {}).get("masked") or {}).get("first_hw_leak_cycle", "n/a")

    # Resolve regions_json relative to the cellift/ directory (report grandparent),
    # not CWD — so the script works correctly when called from any working directory.
    if report_path is not None:
        base_dir = Path(report_path).resolve().parent.parent
    else:
        base_dir = Path(".").resolve()
    regions_json = manifest.get("unmasked", {}).get("regions_json", ".")
    results_root = (base_dir / regions_json).resolve().parent.parent
    unmasked_welch = results_root / "unmasked" / "welch_summary.txt"
    masked_welch = results_root / "masked" / "welch_summary.txt"
    u_info = parse_tvla_summary(unmasked_welch)
    masked_skipped = manifest.get("masked") is None
    m_info = parse_tvla_summary(masked_welch)  # returns zeros if file absent

    def _metric_str(info: dict, counter: str, skipped: bool = False) -> str:
        if skipped:
            return "n/a (evaluation skipped)"
        if info["welch_applicable"]:
            return f"{info['max_t'][counter]:.4f}"
        return f"{info['max_diff'][counter]} (between-group max Δ, Welch n/a)"

    def _metric_label(info: dict, skipped: bool = False) -> str:
        if skipped:
            return "Welch max |t|"
        return "Welch max |t|" if info["welch_applicable"] else "max leakage metric"

    u_cov_num, u_cov_den = coverage_text(report, "unmasked")
    m_cov_num, m_cov_den = coverage_text(report, "masked")

    lines: List[str] = []
    lines.append("# Publication Summary (Refined Root-Cause)")
    lines.append("")
    lines.append("## Headline Metrics")
    lines.append("")
    lines.append(f"- Unmasked first HW leak cycle: {unmasked_first}")
    lines.append(f"- Masked first HW leak cycle: {masked_first}")
    lines.append(f"- Unmasked top-interval coverage (signal+instruction): {u_cov_num}/{u_cov_den}")
    lines.append(f"- Masked top-interval coverage (signal+instruction): {m_cov_num}/{m_cov_den}")
    lines.append("")
    u_lbl = _metric_label(u_info)
    lines.append(f"- Unmasked LC {u_lbl}: {_metric_str(u_info, 'leakage_counter_t0')}")
    lines.append(f"- Unmasked HW {u_lbl}: {_metric_str(u_info, 'hamming_weight_counter_t0')}")
    lines.append(f"- Unmasked HD {u_lbl}: {_metric_str(u_info, 'hamming_distance_counter_t0')}")
    m_lbl = _metric_label(m_info, skipped=masked_skipped)
    lines.append(f"- Masked LC {m_lbl}: {_metric_str(m_info, 'leakage_counter_t0', skipped=masked_skipped)}")
    lines.append(f"- Masked HW {m_lbl}: {_metric_str(m_info, 'hamming_weight_counter_t0', skipped=masked_skipped)}")
    lines.append(f"- Masked HD {m_lbl}: {_metric_str(m_info, 'hamming_distance_counter_t0', skipped=masked_skipped)}")
    lines.append("")
    lines.append("## Refined Interval Table")
    lines.append("")
    lines.append(f"Full machine-readable table: {csv_name}")
    lines.append("")
    lines.append("| Group | Counter | Interval | Peak cycle | Peak |t| | Signal | Instruction | Source |")
    lines.append("|---|---|---:|---:|---:|---|---|---|")

    for row in rows:
        peak_t = row["peak_t"]
        peak_t_str = f"{peak_t:.4f}" if isinstance(peak_t, (int, float)) else "n/a"
        lines.append(
            f"| {row['group']} | {row['counter']} | {row['interval']} | {row['peak_cycle']} | {peak_t_str} | {row['signal']} | {row['instruction']} | {row.get('source', 'n/a')} |"
        )

    lines.append("")

    # Masking candidates section — from data-signal attribution in report JSON.
    all_candidates: List[dict] = []
    for group_key in ("unmasked", "masked"):
        g = (report.get("summary") or {}).get(group_key) or {}
        for cand in g.get("masking_candidates") or []:
            all_candidates.append(cand)
    # Deduplicate by signal path, summing HW diff.
    seen: dict = {}
    for cand in all_candidates:
        sig = cand["signal"]
        if sig not in seen:
            seen[sig] = dict(cand)
        else:
            seen[sig]["total_hw_diff"] += cand["total_hw_diff"]
            seen[sig]["leaky_interval_count"] = max(
                seen[sig]["leaky_interval_count"], cand["leaky_interval_count"]
            )
    ranked_cands = sorted(seen.values(), key=lambda x: -x["total_hw_diff"])

    if ranked_cands:
        lines.append("## Masking Candidates")
        lines.append("")
        lines.append(
            "Signals with highest key-dependent data divergence (vanilla VCD XOR). "
            "Primary targets for hardware masking."
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

    # ── Leakage Narrative ──────────────────────────────────────────────────────
    summary = report.get("summary", {})
    narrative_groups = [
        ("unmasked", summary.get("unmasked")),
        ("masked",   summary.get("masked")),
    ]
    narrative_lines = []
    for grp_name, grp_data in narrative_groups:
        if grp_data is None:
            continue
        nl = generate_leakage_narrative(grp_data, grp_name)
        if nl:
            narrative_lines.extend(nl)

    if narrative_lines:
        lines.append("## Leakage Narrative")
        lines.append("")
        lines.append(
            "Automatic classification of RTL leakage sources by signal type and "
            f"cryptographic data-flow role ({manifest.get('workload', 'crypto').upper()})."
        )
        lines.append("")
        lines.extend(narrative_lines)

    path.write_text("\n".join(lines))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifest", help="Path to run manifest JSON")
    ap.add_argument("report_json", help="Path to root cause report JSON")
    ap.add_argument(
        "--out-prefix",
        default="publication_summary_refined",
        help="Output prefix for markdown/csv summary files",
    )
    args = ap.parse_args()

    _ = load_json(Path(args.manifest))
    report = load_json(Path(args.report_json))

    rows = collect_table_rows(report)
    rows.sort(
        key=lambda r: (
            0 if r["group"] == "unmasked" else 1,
            0 if r["counter"] == "hamming_weight_counter_t0" else 1,
            -(r["peak_t"] if isinstance(r["peak_t"], (int, float)) else float("-inf")),
        )
    )

    out_prefix = Path(args.out_prefix)
    md_path = Path(str(out_prefix) + ".md")
    csv_path = Path(str(out_prefix) + ".csv")

    write_csv(csv_path, rows)
    write_md(md_path, report, rows, csv_path.name, report_path=Path(args.report_json))

    print(f"Publication summary markdown -> {md_path}")
    print(f"Publication summary csv      -> {csv_path}")


if __name__ == "__main__":
    main()
