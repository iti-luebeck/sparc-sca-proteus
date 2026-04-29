RISCV_TOOLS ?= /mnt/nvme1n1p1/chipyard-1.11.0/.conda-env/riscv-tools
RISCV_PREFIX ?= $(if $(RISCV),$(RISCV)/bin/riscv64-unknown-elf,$(RISCV_TOOLS)/bin/riscv64-unknown-elf)

# Proteus is RV32IM (no compressed extension)
RV_ARCH_FLAGS ?= -march=rv32im -mabi=ilp32
RISCV_GCC_OPTS ?= $(RV_ARCH_FLAGS) -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf -fno-tree-loop-distribute-patterns -gdwarf-2
LDFLAGS = -Tlink.ld -static -nostdlib -nostartfiles -lm -lgcc
RISCV_OBJDUMP ?= $(RISCV_PREFIX)-objdump -d

CC = $(RISCV_PREFIX)-gcc

SRCS = main.S aes128_masked.c

build/app.elf: $(SRCS) link.ld | build
	$(CC) $(RISCV_GCC_OPTS) $(SRCS) -o $@ $(LDFLAGS)
	$(RISCV_OBJDUMP) $@ > $@.dump

build:
	mkdir -p build

.PHONY: clean
clean:
	rm -rf build
