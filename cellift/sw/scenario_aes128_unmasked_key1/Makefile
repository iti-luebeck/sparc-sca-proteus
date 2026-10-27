# Toolchain: $RISCV is set inside Docker and by env.sh.  SPARC_SCA_RISCV_BIN is
# an escape hatch for a toolchain installed elsewhere (e.g. a Chipyard conda
# env); otherwise riscv64-unknown-elf-* is resolved from PATH, so a native
# install works without editing this file.
# compile_scenarios.sh also passes RISCV_PREFIX= on the command line, which
# overrides all of these.
RISCV_PREFIX ?= $(if $(RISCV),$(RISCV)/bin/riscv64-unknown-elf,$(if $(SPARC_SCA_RISCV_BIN),$(SPARC_SCA_RISCV_BIN)/riscv64-unknown-elf,riscv64-unknown-elf))
# Proteus is RV32IM (no compressed extension)
RV_ARCH_FLAGS ?= -march=rv32im -mabi=ilp32
RISCV_GCC_OPTS ?= $(RV_ARCH_FLAGS) -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf -fno-tree-loop-distribute-patterns -gdwarf-2
LDFLAGS = -Tlink.ld -static -nostdlib -nostartfiles -lm -lgcc
RISCV_OBJDUMP ?= $(RISCV_PREFIX)-objdump -d

CC = $(RISCV_PREFIX)-gcc

SRCS = main.S aes128_unmasked.c

build/app.elf: $(SRCS) link.ld | build
	$(CC) $(RISCV_GCC_OPTS) $(SRCS) -o $@ $(LDFLAGS)
	$(RISCV_OBJDUMP) $@ > $@.dump

build:
	mkdir -p build

.PHONY: clean
clean:
	rm -rf build
