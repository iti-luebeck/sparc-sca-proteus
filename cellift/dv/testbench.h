// Proteus CellIFT Testbench Header
// Adapted from CellIFT ibex testbench (Flavien Solt, ETH Zurich)

#include "Vproteus_tiny_soc.h"
#include "verilated.h"

#if VM_TRACE
#if VM_TRACE_FST
#include <verilated_fst_c.h>
#else
#include <verilated_vcd_c.h>
#endif // VM_TRACE_FST
#endif // VM_TRACE

#include <iostream>
#include <stdlib.h>

#ifndef TESTBENCH_H
#define TESTBENCH_H

const int kResetLength = 5;
#if VM_TRACE
const int kTraceLevel = 6;
#endif // VM_TRACE

typedef Vproteus_tiny_soc Module;

class Testbench {
 public:
  Testbench(const std::string &trace_filename = "")
      : module_(new Module), tick_count_(0l) {
#if VM_TRACE
#if VM_TRACE_FST
    trace_ = new VerilatedFstC;
#else
    trace_ = new VerilatedVcdC;
#endif // VM_TRACE_FST
    module_->trace(trace_, kTraceLevel);
    trace_->open(trace_filename.c_str());
#endif // VM_TRACE
  }

  ~Testbench(void) { close_trace(); }

  // Proteus uses active-high reset (reset=1 to reset, reset=0 to run)
  void reset(void) {
    module_->rst_ni = 0;  // Assert reset (active-high mapped to active-low wrapper)
    this->tick(1);
    module_->rst_ni = 1;  // Release reset
    this->tick(kResetLength);
  }

  void close_trace(void) {
#if VM_TRACE
    trace_->close();
#endif // VM_TRACE
  }

  bool tick(int num_ticks = 1, bool false_tick = false) {
    for (size_t i = 0; i < num_ticks || num_ticks == -1; i++) {
      tick_count_++;

      module_->clk_i = 0;
      module_->eval();

#if VM_TRACE
      trace_->dump(5 * tick_count_ - 1);
#endif // VM_TRACE

      module_->clk_i = !false_tick;
      module_->eval();

#if VM_TRACE
      trace_->dump(5 * tick_count_);
#endif // VM_TRACE

      module_->clk_i = 0;
      module_->eval();

#if VM_TRACE
      trace_->dump(5 * tick_count_ + 2);
#if !VM_TRACE_FST
      trace_->flush();  // VCD only: per-tick flush. FST uses large auto-flush blocks;
                        // per-tick fstWriterFlushContextPrivate() is 200x slower.
#endif // !VM_TRACE_FST
#endif // VM_TRACE
    }
    return false;
  }

  std::unique_ptr<Module> module_;
 private:
  vluint32_t tick_count_;

#if VM_TRACE
#if VM_TRACE_FST
  VerilatedFstC *trace_;
#else
  VerilatedVcdC *trace_;
#endif // VM_TRACE_FST
#endif // VM_TRACE
};

#endif // TESTBENCH_H
