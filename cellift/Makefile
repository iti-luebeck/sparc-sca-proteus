# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2024-2026 Andrija Neskovic, University of Luebeck

# Proteus evaluation simulator build.
#
# Proteus is a SpinalHDL-generated design.  Core.v (the SpinalHDL output) must
# exist at ../Core.v relative to this Makefile.  The RTL instrumentation is
# performed by Yosys inside this Makefile (make generated/out/cellift.sv), and
# the resulting simulators are built by make build-eval-sims.
#
# Usage:
#   make before_instrumentation   generate vanilla.sv from Core.v
#   make generated/out/cellift.sv  instrument with Yosys + compaction
#   make build-eval-sims          build all five evaluation simulators
#   make clean                    remove build/, traces/, results/ and generated scenarios

ifeq "" "$(CELLIFT_ENV_SOURCED)"
$(error Please source env.sh first — see README.md)
endif

PYTHON ?= python3

TOP_EXECUTABLE_NAME = Vproteus_tiny_soc
TOP_MODULE          = Core
RESOURCEWRAPPER_TAG = proteus

EVAL_SIM_CSVLOG        = build/run_cellift_csvlog_0.1/default-verilator/$(TOP_EXECUTABLE_NAME)
EVAL_SIM_FASTTRACE     = build/run_cellift_fasttrace_0.1/default-verilator/$(TOP_EXECUTABLE_NAME)
EVAL_SIM_FASTTRACE_FST = build/run_cellift_fasttrace_fst_0.1/default-verilator/$(TOP_EXECUTABLE_NAME)
EVAL_SIM_VANILLA       = build/run_vanilla_trace_0.1/default-verilator/$(TOP_EXECUTABLE_NAME)
EVAL_SIM_VANILLA_FST   = build/run_vanilla_trace_fst_0.1/default-verilator/$(TOP_EXECUTABLE_NAME)

.PHONY: generate-rtl before_instrumentation build-eval-sims clean

# ── SpinalHDL RTL generation ──────────────────────────────────────────────────

# Explicit target to (re-)generate Core.v from the SpinalHDL sources.
# Run manually when the Scala sources change: make generate-rtl
generate-rtl:
	@command -v sbt >/dev/null 2>&1 || { \
	  echo ""; \
	  echo "ERROR: sbt not found.  Install OpenJDK 17 and sbt, then re-run."; \
	  echo "  Ubuntu:  sudo apt-get install default-jdk sbt"; \
	  echo "  Or run inside the sparc-sca Docker container."; \
	  echo ""; \
	  exit 1; }
	cd .. && sbt "runMain riscv.CoreDynamicExtMem"

# Auto-generate Core.v via SpinalHDL if it is missing.
# Triggered automatically by: make before_instrumentation
../Core.v:
	@echo ""
	@echo "Core.v not found — running SpinalHDL elaboration (requires sbt + Java 17)."
	@echo "This may take several minutes on first run while SBT resolves dependencies."
	@echo ""
	$(MAKE) generate-rtl

# ── Directory creation ──────────────────────────────────────────────────────────────

generated generated/out logs:
	mkdir -p $@

# ── RTL instrumentation ────────────────────────────────────────────────────────

# Step 0: vanilla.sv = Core.v verbatim (single design source for Yosys).
# If Core.v is absent the ../Core.v rule above auto-generates it via sbt.
generated/out/vanilla.sv: ../Core.v | generated/out
	cp $< $@

generated/out/vanilla.sv.log: | generated/out
	touch $@

before_instrumentation: generated/out/vanilla.sv

# Step 1: Yosys CellIFT instrumentation → cellift_precompact.sv
generated/out/cellift_precompact.sv: $(CELLIFT_YS)/instrument.ys.tcl generated/out/vanilla.sv | generated/out logs
	DECOMPOSE_MEMORY=1 \
	VERILOG_INPUT=$(word 2,$^) \
	INSTRUMENTATION=cellift \
	VERILOG_OUTPUT=$@ \
	TOP_MODULE=$(TOP_MODULE) \
	$(CELLIFT_META_ROOT)/resourcewrapper $(RESOURCEWRAPPER_TAG) cellift instr \
	yosys -DSYNTHESIS -c $< -l $@.log

# Step 2: Compaction pipeline → cellift.sv
generated/out/cellift.sv: generated/out/cellift_precompact.sv | generated/out
	$(PYTHON) $(CELLIFT_PYTHON_COMMON)/expand_left_operand.py $< generated/interm.sv
	$(PYTHON) $(CELLIFT_PYTHON_COMMON)/expand_right_operand.py $< generated/interm.sv
	$(PYTHON) $(CELLIFT_PYTHON_COMMON)/compress_concats.py generated/interm.sv generated/interm.sv
	$(PYTHON) $(CELLIFT_PYTHON_COMMON)/divide_concat_into_subconcats.py generated/interm.sv generated/interm.sv
	cat generated/interm.sv > $@
	rm -f generated/interm.sv
	cp $<.log $@.log

# ── Simulator builds ─────────────────────────────────────────────────────────

build-eval-sims: generated/out/cellift.sv \
    $(EVAL_SIM_CSVLOG) $(EVAL_SIM_FASTTRACE) $(EVAL_SIM_FASTTRACE_FST) \
    $(EVAL_SIM_VANILLA) $(EVAL_SIM_VANILLA_FST)

$(EVAL_SIM_CSVLOG): generated/out/cellift.sv
	rm -f fusesoc.conf
	fusesoc library add run_cellift_csvlog .
	fusesoc --cores-root=. run --build run_cellift_csvlog

$(EVAL_SIM_FASTTRACE): generated/out/cellift.sv
	rm -f fusesoc.conf
	fusesoc library add run_cellift_fasttrace .
	fusesoc --cores-root=. run --build run_cellift_fasttrace

$(EVAL_SIM_FASTTRACE_FST): generated/out/cellift.sv
	rm -f fusesoc.conf
	fusesoc library add run_cellift_fasttrace_fst .
	fusesoc --cores-root=. run --build run_cellift_fasttrace_fst

$(EVAL_SIM_VANILLA):
	rm -f fusesoc.conf
	fusesoc library add run_vanilla_trace .
	fusesoc --cores-root=. run --build run_vanilla_trace

$(EVAL_SIM_VANILLA_FST):
	rm -f fusesoc.conf
	fusesoc library add run_vanilla_trace_fst .
	fusesoc --cores-root=. run --build run_vanilla_trace_fst

clean:
	rm -rf build/ traces/ results/ results_aes/ results_kyber/
	find sw -maxdepth 1 -type d -name 'multi_*' 2>/dev/null | xargs -r rm -rf
	rm -f *.log fusesoc.conf
