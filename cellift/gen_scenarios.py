#!/usr/bin/env python3
"""
gen_scenarios.py - Generate matched-pair TVLA scenarios.

Default profile is AES with two variants:
  - unmasked
  - masked

Extension hook:
  Add a new entry in WORKLOADS with template scenario names and patch labels,
  then call this script with --workload <name>.
"""

import argparse
import hashlib
import json
import random
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent

WORKLOADS = {
    "aes": {
        "templates": {
            "unmasked": {
                "a": "scenario_aes128_unmasked_key1",
                "b": "scenario_aes128_unmasked_key2",
            },
            "masked": {
                "a": "scenario_aes128_masked_key",
                "b": "scenario_aes128_masked_key2",
            },
        },
        "patch_labels": {
            "unmasked": [("aes_plaintext", 16)],
            "masked": [("aes_plaintext", 16), ("aes_state_mask", 16)],
        },
        "protected_labels": {
            "aes_key": 16,
            "aes_key_share0": 16,
            "aes_key_mask": 16,
        },
    },
    "kyber": {
        # Kyber-512 unmasked decapsulation TVLA.
        # Operation under test: crypto_kem_dec(ss, ct, sk)
        # Group A uses key1, Group B uses key2. Per-trace: ct is randomised.
        # sk (1632 bytes) is the taint source; ct (768 bytes) is the variable input.
        "templates": {
            "unmasked": {
                "a": "scenario_kyber_unmasked_key1",
                "b": "scenario_kyber_unmasked_key2",
            },
        },
        "patch_labels": {
            "unmasked": [("kyber_ct", 768)],   # 192 x 4-byte chunks
        },
        "protected_labels": {
            "kyber_sk": 1632,                  # must not change within a group
        },
    },
}


# ── Fixed key ───────────────────────────────────────────────────────────────
#
# The fixed key is an experimental VARIABLE, not a property of a template.
# A fixed-vs-random-key statistic on a Hamming-weight model scales with
# |HW(k) - 64|, because the random group draws keys of expected weight 64, so
# quoting one key quotes one point on that curve. KNOWN_KEYS spans the range
# deliberately: HW 65, 96, 64 and 32.
KNOWN_KEYS = {
    "k1": "2b7e151628aed2a6abf7158809cf4f3c",   # FIPS-197 App. B,   HW 65
    "k2": "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",   # high weight,       HW 96
    "k3": "8da93f17c25e6b04e17a952c38d046bf",   # high entropy,      HW 64
    "k4": "000102030405060708090a0b0c0d0e0f",   # NIST App. C.1,     HW 32
}


def resolve_key(spec: str) -> bytes:
    """A KNOWN_KEYS name or 32 hex digits."""
    if spec in KNOWN_KEYS:
        spec = KNOWN_KEYS[spec]
    raw = bytes.fromhex(spec)
    if len(raw) != 16:
        raise ValueError(f"key must be 16 bytes, got {len(raw)}")
    return raw


def set_key(src: str, key: bytes, rng: random.Random) -> str:
    """Write `key` into whichever key labels the template carries.

    A template keeps its key either in the clear (aes_key) or already split
    (aes_key_share0 and aes_key_mask); the three cores do not agree on which.
    A split template is rewritten as a fresh split of the same key, so the
    invariant share0 ^ mask == key still holds.
    """
    if re.search(r"^[ \t]*aes_key:[ \t]*$", src, re.M):
        return replace_label_bytes(src, "aes_key", key)
    if re.search(r"^[ \t]*aes_key_share0:[ \t]*$", src, re.M):
        mask = bytes(rng.randint(0, 255) for _ in range(16))
        share = bytes(a ^ b for a, b in zip(key, mask))
        src = replace_label_bytes(src, "aes_key_share0", share)
        src = replace_label_bytes(src, "aes_key_mask", mask)
        return src
    raise RuntimeError("template carries neither aes_key nor aes_key_share0")


def bytes_to_asm(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        lines.append("    .byte " + ", ".join(f"0x{x:02x}" for x in chunk))
    return "\n".join(lines)


def replace_label_bytes(src: str, label: str, new_bytes: bytes) -> str:
    n_lines = len(new_bytes) // 4
    if len(new_bytes) % 4 != 0:
        raise ValueError(f"Label '{label}' byte count must be divisible by 4")

    pattern = re.compile(
        r"([ \t]*" + re.escape(label) + r":\n)"
        r"(?:[ \t]*\.byte[^\n]*\n){" + str(n_lines) + r"}",
        re.MULTILINE,
    )
    replacement = r"\1" + bytes_to_asm(new_bytes) + "\n"
    out, count = pattern.subn(replacement, src)
    if count != 1:
        raise ValueError(f"Label '{label}' expected once in main.S, found {count}")
    return out


def verify_protected(src: str, ref: str, protected: dict) -> None:
    for label, n_bytes in protected.items():
        n_lines = n_bytes // 4
        pattern = re.compile(
            r"[ \t]*" + re.escape(label) + r":\n"
            r"((?:[ \t]*\.byte[^\n]*\n){" + str(n_lines) + r"})",
            re.MULTILINE,
        )
        m_ref = pattern.search(ref)
        m_new = pattern.search(src)
        if m_ref and m_new and m_ref.group(1) != m_new.group(1):
            raise RuntimeError(f"Protected label '{label}' was modified")


def _extract_label_bytes(src: str, label: str, n_bytes: int) -> bytes:
    n_lines = n_bytes // 4
    pattern = re.compile(
        r"[ \t]*" + re.escape(label) + r":\n"
        r"((?:[ \t]*\.byte[^\n]*\n){" + str(n_lines) + r"})",
        re.MULTILINE,
    )
    m = pattern.search(src)
    if not m:
        return b""
    out = []
    for ln in m.group(1).splitlines():
        items = ln.split(".byte", 1)[1].split(",")
        for it in items:
            v = it.strip().lower()
            if v.startswith("0x"):
                out.append(int(v, 16))
            else:
                out.append(int(v, 10))
    return bytes(out)


def generate(workload: str, scenario_type: str, group: str, idx: int,
             seed_val: int, key_spec: str = None,
             out_name: str = None, patch: bool = True) -> dict:
    profile = WORKLOADS[workload]
    template = profile["templates"][scenario_type][group]

    src_sw = SCRIPT_DIR / "sw" / template
    src_taint = SCRIPT_DIR / "taint_data" / template

    out_name = out_name or f"multi_{workload}_{scenario_type}_{group}_{idx:03d}"
    out_sw = SCRIPT_DIR / "sw" / out_name
    out_taint = SCRIPT_DIR / "taint_data" / out_name

    if out_sw.exists():
        shutil.rmtree(out_sw)
    shutil.copytree(src_sw, out_sw)

    build_dir = out_sw / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)

    main_s = out_sw / "main.S"
    original = main_s.read_text()
    if key_spec:
        # Applied to `original`, not only to the edited copy: the key labels sit
        # in protected_labels, and verify_protected() below compares the two. An
        # override written to `edited` alone would be rejected as tampering.
        original = set_key(original, resolve_key(key_spec),
                           random.Random(seed_val ^ 0x4B4559))
    edited = original

    rng = random.Random(seed_val)
    if patch:
        for label, n_bytes in profile["patch_labels"][scenario_type]:
            data = bytes(rng.randint(0, 255) for _ in range(n_bytes))
            edited = replace_label_bytes(edited, label, data)

    verify_protected(edited, original, profile["protected_labels"])
    main_s.write_text(edited)

    if out_taint.exists():
        shutil.rmtree(out_taint)
    shutil.copytree(src_taint, out_taint)

    patched = {}
    for label, n_bytes in profile["patch_labels"][scenario_type]:
        blob = _extract_label_bytes(edited, label, n_bytes)
        patched[label] = {
            "bytes_hex": blob.hex(),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "length": len(blob),
        }

    main_hash = hashlib.sha256(edited.encode("utf-8")).hexdigest()
    taint_file = out_taint / "taint_data.txt"
    taint_hash = hashlib.sha256(taint_file.read_bytes()).hexdigest() if taint_file.is_file() else None

    print(f"  {out_name}")
    return {
        "scenario": out_name,
        "index": int(idx),
        "seed_per_trace": int(seed_val),
        "template": template,
        "key": key_spec,
        "key_hex": resolve_key(key_spec).hex() if key_spec else None,
        "main_s_sha256": main_hash,
        "taint_data_sha256": taint_hash,
        "patched_labels": patched,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workload", default="aes", choices=sorted(WORKLOADS.keys()))
    ap.add_argument("--type", required=True)
    ap.add_argument("--group", required=True, choices=["a", "b"])
    ap.add_argument("--n", required=True, type=int)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--key", default=None,
                    help="fixed key for THIS group: a KNOWN_KEYS name "
                         "(k1..k4) or 32 hex digits. Applies to the group "
                         "being generated, so pass it to one group only.")
    ap.add_argument("--attr", metavar="NAME", default=None,
                    help="emit ONE scenario called NAME instead of the "
                         "multi_* series, with --key applied and the per-trace "
                         "labels left at their template values. Root-cause "
                         "attribution runs on a single pair of scenarios and "
                         "has to see the same key as the TVLA arm did.")
    args = ap.parse_args()

    if args.type not in WORKLOADS[args.workload]["templates"]:
        valid = ", ".join(sorted(WORKLOADS[args.workload]["templates"].keys()))
        sys.exit(f"ERROR: unsupported --type '{args.type}' for workload '{args.workload}'. Valid: {valid}")

    if args.attr:
        print(f"Generating attribution scenario {args.attr}: "
              f"workload={args.workload} type={args.type} group={args.group} "
              f"key={args.key or 'template'}")
        row = generate(args.workload, args.type, args.group, 0,
                       seed_val=args.seed * 10000, key_spec=args.key,
                       out_name=args.attr, patch=False)
        print(f"Done. Scenario: {row['scenario']}")
        return

    print(
        f"Generating {args.n} scenarios: workload={args.workload} type={args.type} group={args.group} seed={args.seed}"
    )

    rows = []
    for i in range(args.n):
        rows.append(generate(args.workload, args.type, args.group, i,
                             seed_val=args.seed * 10000 + i,
                             key_spec=args.key))

    prefix = f"multi_{args.workload}_{args.type}_{args.group}"
    manifest_dir = SCRIPT_DIR / "sw" / "_manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{prefix}_manifest.json"
    manifest = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "workload": args.workload,
        "type": args.type,
        "group": args.group,
        "n": int(args.n),
        "seed": int(args.seed),
        "key": args.key,
        "matched_pair_key": "seed_per_trace = seed * 10000 + index",
        "prefix": prefix,
        "scenarios": rows,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"Done. Prefix: {prefix}")
    print(f"Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
