// Proteus CellIFT Per-Cycle CSV Logger
// Drives the simulation tick-by-tick and writes the three leakage counters to
// a CSV file at every clock cycle, enabling TVLA analysis without VCD parsing.
//
// Environment variables:
//   SIMLEN    — total simulation ticks (same as other toplevels)
//   TRACEFILE — VCD output path (set to /dev/null to suppress)
//   CSVFILE   — output CSV path (required)
//   SIMSRAMELF, SIMSRAMTAINT — passed through to the testbench/elfloader

#include "testbench.h"
#include "ticks.h"

#ifndef IS_VANILLA
#include "Vproteus_tiny_soc___024root.h"
#endif

#include <fstream>
#include <iostream>
#include <cstdlib>

int main(int argc, char **argv, char **env) {
  Verilated::commandArgs(argc, argv);
  Verilated::traceEverOn(VM_TRACE);

  const char *csvfile_env = std::getenv("CSVFILE");
  if (!csvfile_env) {
    std::cerr << "CSVFILE environment variable not set." << std::endl;
    return 1;
  }

  std::cout << "Starting CellIFT CSV logger." << std::endl;

  int simlen = get_sim_length_cycles(LEADTICKS);

  Testbench *tb = new Testbench(cl_get_tracefile());
  tb->reset();

#ifndef IS_VANILLA
  auto *rootp = tb->module_->rootp;
#endif

  std::ofstream csv(csvfile_env);
  if (!csv.is_open()) {
    std::cerr << "Cannot open CSVFILE: " << csvfile_env << std::endl;
    return 1;
  }
  csv << "cycle,leakage_counter_t0,hamming_weight_counter_t0,hamming_distance_counter_t0\n";

  for (int cycle = 0; cycle < simlen; cycle++) {
    tb->tick(1);

#ifndef IS_VANILLA
    csv << cycle << ","
        << rootp->proteus_tiny_soc__DOT__leakage_counter_t0 << ","
        << rootp->proteus_tiny_soc__DOT__hamming_weight_counter_t0 << ","
        << rootp->proteus_tiny_soc__DOT__hamming_distance_counter_t0 << "\n";
#else
    csv << cycle << ",0,0,0\n";
#endif
  }

  csv.close();

  std::cout << "Testbench CSV complete. Cycles logged: " << simlen << std::endl;
  std::cout << "CSV written to " << csvfile_env << std::endl;

#ifndef IS_VANILLA
  std::cout << "=== CellIFT Leakage Counters ===" << std::endl;
  std::cout << "leakage_counter_t0:          " << std::dec
            << rootp->proteus_tiny_soc__DOT__leakage_counter_t0 << std::endl;
  std::cout << "hamming_weight_counter_t0:   " << std::dec
            << rootp->proteus_tiny_soc__DOT__hamming_weight_counter_t0 << std::endl;
  std::cout << "hamming_distance_counter_t0: " << std::dec
            << rootp->proteus_tiny_soc__DOT__hamming_distance_counter_t0 << std::endl;
#endif

  delete tb;
  return 0;
}
