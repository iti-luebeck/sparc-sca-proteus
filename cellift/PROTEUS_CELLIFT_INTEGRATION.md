# Proteus Dynamic OoO Core — CellIFT Leakage Integration

## Overview

This directory contains the CellIFT (Cell-level Information Flow Tracking) integration for the **Proteus dynamic out-of-order superscalar RISC-V core** (RV32IM). It instruments the processor RTL with taint propagation logic and builds Verilator simulators that track information leakage through power side channels (Hamming weight/distance). A full TVLA (Test Vector Leakage Assessment) pipeline is provided, including per-cycle leakage CSV logging, statistical analysis, RTL signal identification, and instruction-level source correlation.

The Proteus core is a SpinalHDL-based design with:
- Dynamic out-of-order execution with register renaming
- 8 parallel ALUs, 2 multiply/divide units
- 3-stage load pipeline, 32-entry reorder buffer
- AXI4 shared bus interface for external memory (128-bit data bus)

---

## Architecture

```
proteus_tiny_soc (wrapper)
├── Core (CellIFT-instrumented or vanilla Proteus SoC)
│   ├── Pipeline (OoO core with taint tracking in CellIFT mode)
│   ├── L1 I-cache and D-cache (write-back)
│   ├── AXI4 crossbar + decoders
│   ├── APB peripherals (timers, charDev, testDev, byteDev)
│   └── Built-in leakage counters (CellIFT only)
└── ift_sram_mem / noift_sram_mem (128-bit wide SRAM)
    └── DPI-C interface for ELF + taint data loading
```

The Core is the AXI **master**. The SRAM is 128-bit wide to match the AXI bus width (single-beat 128-bit transfers, no bursts).

### Signal Categories (CellIFT mode)

| Signal suffix | Description |
|---------------|-------------|
| (none)        | Original functional signals |
| `_t0`         | Taint bit mirroring each functional signal (1 = tainted by secret) |
| `_leak0`      | `data AND taint` — actual key-dependent values at bus boundaries |

### Built-in Leakage Counters (CellIFT mode)

| Counter | Description |
|---------|-------------|
| `leakage_counter_t0` | Total tainted signal transitions |
| `hamming_weight_counter_t0` | Cumulative Hamming weight of tainted values |
| `hamming_distance_counter_t0` | Cumulative Hamming distance between consecutive tainted values |

---

## Directory Structure

```
cellift-proteus/
├── Core.v                              # SpinalHDL-generated Verilog (287k lines)
└── cellift/
    ├── PROTEUS_CELLIFT_INTEGRATION.md  # This file
    ├── CELLIFT_TVLA_EVALUATION.md      # Full evaluation reference + porting guide
    │
    ├── ── FuseSoC build configs ──────────────────────────────────────────
    ├── run_cellift_trace.core          # CellIFT build with -O0 (reference, slow)
    ├── run_cellift_fasttrace.core      # CellIFT build with -O2 (75k cycles/min)
    ├── run_cellift_csvlog.core         # CellIFT build: per-cycle CSV logger
    ├── run_vanilla_trace.core          # Vanilla (no taint) build
    ├── fusesoc.conf
    │
    ├── ── RTL wrappers ───────────────────────────────────────────────────
    ├── src/
    │   ├── proteus_tiny_soc_taints.sv  # CellIFT wrapper (taint ports + ift_sram_mem)
    │   ├── proteus_tiny_soc.sv         # Vanilla wrapper
    │   ├── ift_sram_mem.sv             # Taint-aware 128-bit SRAM
    │   └── ift_sram_mem_notaint.sv     # Vanilla 128-bit SRAM
    │
    ├── ── Testbench / C++ drivers ────────────────────────────────────────
    ├── dv/
    │   ├── testbench.h                 # Verilator testbench (clock, reset, VCD)
    │   ├── toplevel.cc                 # Standard driver: prints final counter values
    │   └── toplevel_csv.cc             # CSV driver: logs counters tick-by-tick
    │
    ├── ── Software scenarios ─────────────────────────────────────────────
    ├── sw/
    │   ├── scenario_aes128_masked_key/    # TVLA Group A — masked AES, NIST key 1
    │   ├── scenario_aes128_masked_key2/   # TVLA Group B — masked AES, NIST key 2
    │   ├── scenario_aes128_unmasked_key1/ # TVLA Group A — unmasked AES, NIST key 1
    │   └── scenario_aes128_unmasked_key2/ # TVLA Group B — unmasked AES, NIST key 2
    │       Each scenario contains: main.S  *.c  link.ld  Makefile  build/app.elf
    │
    ├── ── Taint configuration ────────────────────────────────────────────
    ├── taint_data/
    │   ├── scenario_aes128_masked_key/taint_data.txt    # offset 0xB00, 16 bytes
    │   ├── scenario_aes128_masked_key2/taint_data.txt   # offset 0xB00, 16 bytes
    │   ├── scenario_aes128_unmasked_key1/taint_data.txt # offset 0x900, 16 bytes
    │   └── scenario_aes128_unmasked_key2/taint_data.txt # offset 0x900, 16 bytes
    │
    ├── ── Shell scripts ──────────────────────────────────────────────────
    ├── run_cellift_sim.sh              # Run CellIFT sim (fasttrace binary)
    ├── run_vanilla_sim.sh              # Run vanilla sim (VCD output)
    ├── run_tvla.sh                     # Full TVLA pipeline (two groups → analysis)
    │
    ├── ── Analysis scripts ───────────────────────────────────────────────
    ├── tvla_analysis.py                # Per-cycle TVLA: first divergence, Welch t-test
    ├── leakage_signals.py              # Signal-level leakage: which RTL signals leak?
    ├── pc_at_leakage.py                # Instruction correlation: which SW instruction?
    │
    ├── ── Generated RTL ──────────────────────────────────────────────────
    ├── generated/out/cellift.sv        # CellIFT-instrumented design (849k lines)
    │
    └── ── Build outputs ──────────────────────────────────────────────────
        ├── traces/                     # VCD output directory
        └── build/
            ├── run_cellift_trace_0.1/      # CellIFT -O0 binary (~235MB)
            ├── run_cellift_fasttrace_0.1/  # CellIFT -O2 binary (~14MB)
            ├── run_cellift_csvlog_0.1/     # CellIFT CSV binary (~14MB)
            └── run_vanilla_trace_0.1/      # Vanilla binary (~25MB)
```

---

## Status: Fully Working

| Component | Status |
|-----------|--------|
| Vanilla simulator | ✅ Working — AES completes at ~22,600 cycles, ciphertext verified |
| CellIFT taint propagation | ✅ Working — taint propagates from key SRAM to leakage counters |
| Fast CellIFT binary (-O2) | ✅ Working — 75,000 cycles/min (1500× speedup over -O0) |
| Per-cycle CSV logging | ✅ Working — `leakage/HW/HD counters` captured each tick |
| TVLA analysis (Python) | ✅ Working — first divergence, Welch t-test, PNG plots |
| Signal-level leakage | ✅ Working — identifies which RTL signals carry tainted data |
| Instruction correlation | ✅ Working — maps leakage cycle → PC → disassembly → source line |

---

## Quick Start

### 1 — Run TVLA (two-scenario comparison)

```bash
cd cellift-proteus/cellift

# Unmasked AES: compare two keys, 1000 cycles, with plots
./run_tvla.sh 1000 tvla_out \
    scenario_aes128_unmasked_key1 \
    scenario_aes128_unmasked_key2 \
    --plot --delta
```

Output: first divergence cycle, leaky cycle count, max/mean |A−B|, PNG plots in `tvla_out/`.

### 2 — Identify which RTL signals are leaking

```bash
# Generate short VCDs (100 cycles covers first leakage at cycle ~37)
./run_cellift_sim.sh 100 /tmp/a.vcd scenario_aes128_unmasked_key1
./run_cellift_sim.sh 100 /tmp/b.vcd scenario_aes128_unmasked_key2

# Find leaking signals at cycles of interest
python3 leakage_signals.py /tmp/a.vcd /tmp/b.vcd \
    --cycles 36 37 38 40 --top 20 --plot
```

### 3 — Correlate to source-level instructions

```bash
# Generate a vanilla VCD (no taint overhead, same timing)
./run_vanilla_sim.sh 100 traces/vanilla_unmasked_key1.vcd \
    scenario_aes128_unmasked_key1

# Map leakage cycles to fetch PC, retire PC, and source lines
python3 pc_at_leakage.py \
    traces/vanilla_unmasked_key1.vcd \
    sw/scenario_aes128_unmasked_key1/build/app.elf \
    --cycles 35 36 37 38 39 40
```

---

## Detailed Tool Reference

### `run_cellift_sim.sh`

```bash
./run_cellift_sim.sh [SIMLEN] [TRACEFILE] [SCENARIO]
# Defaults: 30000  /dev/null  scenario_aes128_masked_key
```

Uses the fast CellIFT binary (`run_cellift_fasttrace`). Set `TRACEFILE=/dev/null` to suppress VCD output when only counter values are needed.

### `run_vanilla_sim.sh`

```bash
./run_vanilla_sim.sh [SIMLEN] [TRACEFILE] [SCENARIO]
# Defaults: 50000  traces/vanilla_aes.vcd  scenario_aes128_masked_key
```

### `run_tvla.sh`

```bash
./run_tvla.sh [SIMLEN] [OUTDIR] [SCENARIO_A] [SCENARIO_B] [--plot] [--delta]
# Defaults: 30000  tvla_out  scenario_aes128_masked_key  scenario_aes128_masked_key2
```

Runs the CSV logger for both groups, then calls `tvla_analysis.py`. `--delta` shows per-cycle increments instead of cumulative counters.

### `tvla_analysis.py`

```bash
python3 tvla_analysis.py <csv_a> <csv_b> [--plot] [--out PREFIX] [--trim-tail N] [--delta]
```

Compares two per-cycle leakage CSV files. Reports:
- First divergence cycle per counter (LC, HW, HD)
- Number of leaky cycles and max/mean |A−B|
- Optional Welch t-test for multi-trace TVLA (`welch_report()`)

### `leakage_signals.py`

```bash
python3 leakage_signals.py <vcd_a> <vcd_b> \
    --cycles N [N ...] [--top K] [--plot]
```

Parses two CellIFT VCDs and, for each requested cycle, ranks RTL signals by the magnitude of their key-dependent difference:
- `_leak0` signals — actual key-dependent values (`data AND taint`)
- `_t0` signals — taint topology differences

Generates `leakage_signals_heatmap.png` and `leakage_signals_timeline.png`.

### `pc_at_leakage.py`

```bash
python3 pc_at_leakage.py <vanilla_vcd> <elf> \
    --cycles N [N ...] [--no-source]
```

For each cycle of interest, reads the vanilla VCD and reports:
- **Fetch PC**: instruction the CPU is fetching at that cycle
- **Retire PC + IR**: instruction being committed (if any)
- **Source line**: function name and file:line from `addr2line`

**Timing formula**: VCD posedge for CSV cycle N = `5 × (7 + N)`.
(6 pre-loop reset ticks in `testbench.h::reset()`, clock period = 10 VCD time units.)

---

## Software Scenarios

| Scenario | Type | Key (hex) | Taint offset |
|----------|------|-----------|--------------|
| `scenario_aes128_masked_key` | Masked AES | NIST key 1 XOR mask → `key_share0` | `0xB00` |
| `scenario_aes128_masked_key2` | Masked AES | NIST key 2 XOR mask → `key_share0` | `0xB00` |
| `scenario_aes128_unmasked_key1` | Unmasked AES | `2b7e151628aed2a6abf7158809cf4f3c` | `0x900` |
| `scenario_aes128_unmasked_key2` | Unmasked AES | `000102030405060708090a0b0c0d0e0f` | `0x900` |

The taint offset is the **byte offset from SRAM base** (`0x80000000`) where the 16-byte key lives. Find it with:

```bash
nm sw/SCENARIO/build/app.elf | grep aes_key
# Subtract 0x80000000 from the address to get the offset
```

### Taint Data Format

`taint_data.txt` — one line per tainted region, **no comments**:

```
<taint_id> <offset_hex> <length_bytes_hex> <taint_mask_hex>
```

Example:
```
0 900 10 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SIMLEN` | Yes | Number of simulation clock cycles |
| `TRACEFILE` | Yes | VCD output path — use `/dev/null` to suppress (~1M signals in CellIFT) |
| `SIMSRAMELF` | Yes | RV32IM ELF binary to load into SRAM |
| `SIMSRAMTAINT` | No | Taint data file path (CellIFT only) |
| `CSVFILE` | No | Per-cycle CSV output path (CSV logger binary only) |

---

## Simulation Timing

```
reset() in testbench.h:
  tick(1)              → assert reset    (tick_count_ = 1)
  tick(kResetLength=5) → hold reset      (tick_count_ = 6)

CSV loop:
  tick(1) per cycle    → tick_count_ = 7 + N for CSV cycle N

VCD posedge dump time = 5 × tick_count_
→ CSV cycle N  =  VCD time 5×(7+N)
→ VCD time T   =  CSV cycle T/5 − 7

Clock period: 10 VCD time units (posedge at 5, 15, 25, …, 5+10×i)
```

---

## Leakage Analysis Results

### Unmasked AES-128

Running TVLA on `scenario_aes128_unmasked_key1` vs `scenario_aes128_unmasked_key2`:

- **First divergence at CSV cycle 36** (HW counter)
- **Leaking signal at cycle 37**: `toplevel_soc_ibusAxi_decoder_io_input_r_rData_data_leak0` (128-bit, HW diff = 63)
- **Instruction at leakage**: `lbu a4,0(a1)` at `0x80000148`
  - Function: `key_expansion` — `aes128_unmasked.c:70`
  - This is `round_keys[i] = key[i]` — the first key byte being copied
- **Root cause**: The `lbu` loads a raw key byte through the shared AXI read-data bus. The return data (`rData`) is tainted and key-dependent, and appears on the instruction bus AXI decoder one cycle after the load is issued.

### Masked AES-128

- **First divergence at CSV cycle 44** (later than unmasked, as expected)
- The masking delays leakage; the key share is XOR'd with a mask before storage

---

## Building Binaries

```bash
source /mnt/nvme1n1p1/cellift-meta-leakage/env.sh

# Fast CellIFT binary (used by run_cellift_sim.sh and run_tvla.sh)
fusesoc --cores-root=. run --build run_cellift_fasttrace

# CSV logger binary (used by run_tvla.sh)
fusesoc --cores-root=. run --build run_cellift_csvlog

# Vanilla binary (used by run_vanilla_sim.sh)
fusesoc --cores-root=. run --build run_vanilla_trace
```

### Building Software

```bash
cd sw/SCENARIO
make clean && make
```

Uses toolchain: `riscv32-unknown-elf-*` from `$PREFIX_CELLIFT/riscv/bin/`
Flags: `-march=rv32im -mabi=ilp32 -O2 -mcmodel=medany`

---

## Memory Map

| Address | Device |
|---------|--------|
| `0x80000000` | External SRAM (ELF load target, boot address) |
| `0x02000000` | Machine timers (APB) |
| `0x10000000` | Character output device (APB) |
| `0x30000000` | Test device (write 0 = pass) |

---

## Bugs Fixed During Integration

| # | Bug | Fix |
|---|-----|-----|
| 1 | Bit replication syntax: `{8{x}, 8{y}}` | → `{{8{x}}, {8{y}}}` |
| 2 | Duplicate pin connections: B/R taint signals tied-off and driven simultaneously | Removed tie-offs |
| 3 | Wrong `_t0` port directions (CellIFT mirrors original direction) | Corrected in wrapper |
| 4 | Core expects 128-bit AXI transfers; SRAM was 32-bit | Replaced with 128-bit `ift_sram_mem` |
| 5 | SRAM writes not executing: `req_i` only set for reads | Set `req_i = axi_arw_valid` for R and W |
| 6 | AXI read data hardcoded to 0 (`rdata_o` unconnected) | Connected `rdata_o` to AXI response |
| 7 | Stack overlapping tainted key data | Reordered linker sections |
| 8 | `taint_data.txt` comments (`#`) parsed as addresses | Removed all comment lines |
| 9 | CellIFT binary 235MB, 50 cycles/min (`-O0 -g`) | New `.core` with `-O2`, no `-g` → 14MB, 75k cycles/min |
| 10 | `rootp->` signal access requires `--trace` flag | All binaries keep `--trace`; set `TRACEFILE=/dev/null` to suppress VCD |

---

## Key Differences from ibex/BOOM Integrations

| Aspect | ibex | BOOM | Proteus |
|--------|------|------|---------|
| ISA | RV32IMC | RV64GC | RV32IM |
| Pipeline | 2-stage in-order | 4-wide OoO | 8-ALU dynamic OoO |
| Bus | Custom TL-UL | AXI4 (64-bit) | AXI4-Shared (128-bit) |
| Clock/Reset | `clk_i`/`rst_ni` | `clock`/`reset` | `clk_i`/`rst_ni` (wrapped) |
| HDL | SystemVerilog | Chisel→Verilog | SpinalHDL→Verilog |
| CellIFT size | ~50k lines | ~400k lines | ~849k lines |
| `DECOMPOSE_MEMORY` | 0 | 0 | 1 (required) |
| L1 Cache | No | Yes | Yes (write-back) |
| Burst AXI | N/A (TL-UL) | Yes | No (single-beat 128-bit) |
