// Proteus CellIFT Toplevel Testbench
// Adapted from CellIFT ibex testbench (Flavien Solt, ETH Zurich)

#include "testbench.h"
#include "ticks.h"

#if !defined(IS_VANILLA) && VM_TRACE
#include "Vproteus_tiny_soc___024root.h"
#endif

long run_test(Testbench *tb, int simlen) {
  return tb_run_ticks(tb, simlen, true);
}

int main(int argc, char **argv, char **env) {

  Verilated::commandArgs(argc, argv);
  Verilated::traceEverOn(VM_TRACE);

  std::cout << "Starting getting env variables." << std::endl;

  int simlen = get_sim_length_cycles(LEADTICKS);

  Testbench *tb = new Testbench(cl_get_tracefile());

  long duration = run_test(tb, simlen);

#if !VM_TRACE
  std::cout << "Testbench complete!" << std::endl;
  std::cout << "Elapsed time: " << std::dec << duration << "." << std::endl;
#else
  std::cout << "Testbench with traces complete!" << std::endl;
  std::cout << "Elapsed time (traces enabled): " << std::dec << duration << "." << std::endl;
#endif

#if !defined(IS_VANILLA) && VM_TRACE
  // Print CellIFT leakage counters
  std::cout << "=== CellIFT Leakage Counters ===" << std::endl;
  std::cout << "leakage_counter_t0:          " << std::dec
            << tb->module_->leakage_counter_t0 << std::endl;
  std::cout << "hamming_weight_counter_t0:   " << std::dec
            << tb->module_->hamming_weight_counter_t0 << std::endl;
  std::cout << "hamming_distance_counter_t0: " << std::dec
            << tb->module_->hamming_distance_counter_t0 << std::endl;
#endif

  delete tb;
  exit(0);
}
