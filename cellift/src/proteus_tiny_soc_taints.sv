// Proteus Dynamic OoO Core - CellIFT Leakage Wrapper
//
// Wraps the CellIFT-instrumented Proteus Core (SoC) with:
// - AXI4 memory slave (with taint tracking via ift_sram_mem)
// - All _leak0 leakage ports connected
// - Leakage counters exposed as top-level outputs
//
// The Proteus Core already includes the SoC infrastructure (AXI crossbar,
// APB peripherals, caches). It exposes a single AXI4 shared port for
// external memory access. Core is AXI master.

module proteus_tiny_soc #(
    parameter int unsigned NumTaints = 1,
    parameter int unsigned NumWords = 1 << 18, // 256K x 128-bit = 4MB
    parameter int unsigned AddrWidth = 32,
    parameter int unsigned DataWidth = 128      // Match AXI bus width
) (
  input logic clk_i,
  input logic rst_ni,

  // ── Leakage counters ────────────────────────────────────────────────
  //
  // Real output PORTS rather than internal `logic` marked
  // (* verilator_public *), so the harness reads them as `tb->module_->...`.
  //
  // Read through Verilator's mangled `rootp->proteus_tiny_soc__DOT__...`
  // names they stop resolving the moment the instrumentation scope widens:
  // with the counters coming straight off the Core instance the wrapper wire
  // becomes a pure pass-through, Verilator collapses it into the Core's own
  // signal, and the `__DOT__` symbol ceases to exist. That is a build
  // failure rather than a wrong number, but it only appears once someone
  // raises POWER_LEAKAGE_SCOPE or POWER_LEAKAGE_FLATTEN. A port cannot be
  // optimised away, so it cannot recur.
  output logic [31:0] leakage_counter_t0,
  output logic [31:0] hamming_weight_counter_t0,
  output logic [31:0] hamming_distance_counter_t0
);

  // =========================================================================
  // AXI4 Shared Bus Signals (Core is master, memory is slave)
  // =========================================================================

  // ARW channel (core -> memory)
  logic        axi_arw_valid;
  logic        axi_arw_ready;
  logic [29:0] axi_arw_payload_addr;
  logic [3:0]  axi_arw_payload_id;
  logic [7:0]  axi_arw_payload_len;
  logic [2:0]  axi_arw_payload_size;
  logic [1:0]  axi_arw_payload_burst;
  logic        axi_arw_payload_write;

  // W channel (core -> memory)
  logic         axi_w_valid;
  logic         axi_w_ready;
  logic [127:0] axi_w_payload_data;
  logic [15:0]  axi_w_payload_strb;
  logic         axi_w_payload_last;

  // B channel (memory -> core)
  logic        axi_b_valid;
  logic        axi_b_ready;
  logic [3:0]  axi_b_payload_id;
  logic [1:0]  axi_b_payload_resp;

  // R channel (memory -> core)
  logic         axi_r_valid;
  logic         axi_r_ready;
  logic [127:0] axi_r_payload_data;
  logic [3:0]   axi_r_payload_id;
  logic [1:0]   axi_r_payload_resp;
  logic         axi_r_payload_last;

  // Peripheral outputs (directly from Core)
  logic        charOut_valid;
  logic [7:0]  charOut_payload;
  logic        testDev_valid;
  logic [31:0] testDev_payload;
  logic        byteDev_wdata_valid;
  logic [7:0]  byteDev_wdata_payload;
  logic        byteDev_rdata_ready;

  // =========================================================================
  // Taint OUTPUTS from Core (_t0 signals that Core drives)
  // =========================================================================

  // ARW/W channel taint outputs (core drives these as master)
  logic        axi_arw_valid_t0;
  logic [29:0] axi_arw_payload_addr_t0;
  logic [3:0]  axi_arw_payload_id_t0;
  logic [7:0]  axi_arw_payload_len_t0;
  logic [2:0]  axi_arw_payload_size_t0;
  logic [1:0]  axi_arw_payload_burst_t0;
  logic        axi_arw_payload_write_t0;
  logic        axi_w_valid_t0;
  logic [127:0] axi_w_payload_data_t0;
  logic [15:0] axi_w_payload_strb_t0;
  logic        axi_w_payload_last_t0;

  // B/R ready taint outputs (core drives ready for response channels)
  logic        axi_b_ready_t0;
  logic        axi_r_ready_t0;

  // Peripheral taint outputs
  logic        charOut_valid_t0;
  logic [7:0]  charOut_payload_t0;
  logic        testDev_valid_t0;
  logic [31:0] testDev_payload_t0;
  logic        byteDev_wdata_valid_t0;
  logic [7:0]  byteDev_wdata_payload_t0;
  logic        byteDev_rdata_ready_t0;

  // =========================================================================
  // Leakage counters (built-in from CellIFT)
  // =========================================================================

  // (declared as output ports above -- the Core instance drives them directly)

  // =========================================================================
  // _leak0 signals from Core (all outputs, connected to capture leakage)
  // =========================================================================

  // AXI interface leakage (directly from core master signals)
  logic        io_axi_r_ready_leak0;
  logic        io_axi_b_ready_leak0;
  logic [29:0] io_axi_arw_payload_addr_leak0;
  logic [127:0] io_axi_w_payload_data_leak0;
  logic        io_axi_arw_payload_write_leak0;
  logic [1:0]  io_axi_arw_payload_burst_leak0;
  logic [3:0]  io_axi_arw_payload_id_leak0;
  logic [7:0]  io_axi_arw_payload_len_leak0;
  logic [2:0]  io_axi_arw_payload_size_leak0;
  logic        io_axi_arw_valid_leak0;
  logic        io_axi_w_payload_last_leak0;
  logic [15:0] io_axi_w_payload_strb_leak0;
  logic        io_axi_w_valid_leak0;

  // AXI taint leakage
  logic [29:0] io_axi_arw_payload_addr_t0_leak0;
  logic [1:0]  io_axi_arw_payload_burst_t0_leak0;
  logic [3:0]  io_axi_arw_payload_id_t0_leak0;
  logic [7:0]  io_axi_arw_payload_len_t0_leak0;
  logic [2:0]  io_axi_arw_payload_size_t0_leak0;
  logic        io_axi_arw_payload_write_t0_leak0;
  logic        io_axi_arw_valid_t0_leak0;
  logic        io_axi_b_ready_t0_leak0;
  logic        io_axi_r_ready_t0_leak0;
  logic [127:0] io_axi_w_payload_data_t0_leak0;
  logic        io_axi_w_payload_last_t0_leak0;
  logic [15:0] io_axi_w_payload_strb_t0_leak0;
  logic        io_axi_w_valid_t0_leak0;

  // Peripheral leakage
  logic        io_byteDev_rdata_ready_leak0;
  logic [7:0]  io_byteDev_wdata_payload_leak0;
  logic        io_byteDev_wdata_valid_leak0;
  logic [7:0]  io_charOut_payload_leak0;
  logic        io_charOut_valid_leak0;
  logic [31:0] io_testDev_payload_leak0;
  logic        io_testDev_valid_leak0;

  // Peripheral taint leakage
  logic        io_byteDev_rdata_ready_t0_leak0;
  logic [7:0]  io_byteDev_wdata_payload_t0_leak0;
  logic        io_byteDev_wdata_valid_t0_leak0;
  logic [7:0]  io_charOut_payload_t0_leak0;
  logic        io_charOut_valid_t0_leak0;
  logic [31:0] io_testDev_payload_t0_leak0;
  logic        io_testDev_valid_t0_leak0;

  // Clock leakage
  logic        clk_leak0;

  // =========================================================================
  // Core Instantiation
  // =========================================================================

  Core i_core (
    .clk     (clk_i),
    .reset   (~rst_ni),     // Proteus: active-high reset

    // -----------------------------------------------------------------------
    // AXI4 shared bus — functional signals
    // -----------------------------------------------------------------------
    // Core outputs (master drives ARW, W channels)
    .io_axi_arw_valid          (axi_arw_valid),
    .io_axi_arw_payload_addr   (axi_arw_payload_addr),
    .io_axi_arw_payload_id     (axi_arw_payload_id),
    .io_axi_arw_payload_len    (axi_arw_payload_len),
    .io_axi_arw_payload_size   (axi_arw_payload_size),
    .io_axi_arw_payload_burst  (axi_arw_payload_burst),
    .io_axi_arw_payload_write  (axi_arw_payload_write),
    .io_axi_w_valid            (axi_w_valid),
    .io_axi_w_payload_data     (axi_w_payload_data),
    .io_axi_w_payload_strb     (axi_w_payload_strb),
    .io_axi_w_payload_last     (axi_w_payload_last),
    .io_axi_b_ready            (axi_b_ready),
    .io_axi_r_ready            (axi_r_ready),

    // Core inputs (slave drives ready, B, R channels)
    .io_axi_arw_ready          (axi_arw_ready),
    .io_axi_w_ready            (axi_w_ready),
    .io_axi_b_valid            (axi_b_valid),
    .io_axi_b_payload_id       (axi_b_payload_id),
    .io_axi_b_payload_resp     (axi_b_payload_resp),
    .io_axi_r_valid            (axi_r_valid),
    .io_axi_r_payload_data     (axi_r_payload_data),
    .io_axi_r_payload_id       (axi_r_payload_id),
    .io_axi_r_payload_resp     (axi_r_payload_resp),
    .io_axi_r_payload_last     (axi_r_payload_last),

    // Peripheral outputs
    .io_charOut_valid           (charOut_valid),
    .io_charOut_payload         (charOut_payload),
    .io_testDev_valid           (testDev_valid),
    .io_testDev_payload         (testDev_payload),
    .io_byteDev_wdata_valid     (byteDev_wdata_valid),
    .io_byteDev_wdata_payload   (byteDev_wdata_payload),
    .io_byteDev_rdata_valid     (1'b0),     // No stdin in CellIFT sim
    .io_byteDev_rdata_payload   (8'b0),
    .io_byteDev_rdata_ready     (byteDev_rdata_ready),

    // -----------------------------------------------------------------------
    // Taint INPUTS — tie off to zero (no taint from memory/peripherals)
    // These are inputs to Core for signals that flow memory->core
    // -----------------------------------------------------------------------
    .clk_t0                          (1'b0),
    .io_axi_arw_ready_t0             (1'b0),   // input: slave ready taint
    .io_axi_w_ready_t0               (1'b0),   // input: slave ready taint
    .io_axi_b_valid_t0               (1'b0),   // input: write response taint
    .io_axi_b_payload_id_t0          (4'b0),
    .io_axi_b_payload_resp_t0        (2'b0),
    .io_axi_r_valid_t0               (1'b0),   // input: read response valid taint
    .io_axi_r_payload_data_t0        (sram_rdata_taint),  // SRAM taint → Core
    .io_axi_r_payload_id_t0          (4'b0),
    .io_axi_r_payload_resp_t0        (2'b0),
    .io_axi_r_payload_last_t0        (1'b0),
    .io_byteDev_rdata_valid_t0       (1'b0),   // input: no stdin taint
    .io_byteDev_rdata_payload_t0     (8'b0),

    // -----------------------------------------------------------------------
    // Taint OUTPUTS — connect to wires (Core computes taint propagation)
    // These are outputs from Core for signals that flow core->memory
    // -----------------------------------------------------------------------
    .io_axi_arw_valid_t0        (axi_arw_valid_t0),
    .io_axi_arw_payload_addr_t0 (axi_arw_payload_addr_t0),
    .io_axi_arw_payload_id_t0   (axi_arw_payload_id_t0),
    .io_axi_arw_payload_len_t0  (axi_arw_payload_len_t0),
    .io_axi_arw_payload_size_t0 (axi_arw_payload_size_t0),
    .io_axi_arw_payload_burst_t0(axi_arw_payload_burst_t0),
    .io_axi_arw_payload_write_t0(axi_arw_payload_write_t0),
    .io_axi_w_valid_t0          (axi_w_valid_t0),
    .io_axi_w_payload_data_t0   (axi_w_payload_data_t0),
    .io_axi_w_payload_strb_t0   (axi_w_payload_strb_t0),
    .io_axi_w_payload_last_t0   (axi_w_payload_last_t0),
    .io_axi_b_ready_t0          (axi_b_ready_t0),
    .io_axi_r_ready_t0          (axi_r_ready_t0),

    // Peripheral taint outputs
    .io_charOut_valid_t0         (charOut_valid_t0),
    .io_charOut_payload_t0       (charOut_payload_t0),
    .io_testDev_valid_t0         (testDev_valid_t0),
    .io_testDev_payload_t0       (testDev_payload_t0),
    .io_byteDev_wdata_valid_t0   (byteDev_wdata_valid_t0),
    .io_byteDev_wdata_payload_t0 (byteDev_wdata_payload_t0),
    .io_byteDev_rdata_ready_t0   (byteDev_rdata_ready_t0),

    // -----------------------------------------------------------------------
    // Built-in leakage counters
    // -----------------------------------------------------------------------
    .leakage_counter_t0          (leakage_counter_t0),
    .hamming_weight_counter_t0   (hamming_weight_counter_t0),
    .hamming_distance_counter_t0 (hamming_distance_counter_t0),

    // -----------------------------------------------------------------------
    // _leak0 ports — AXI interface (all outputs from Core)
    // -----------------------------------------------------------------------
    .clk_leak0                         (clk_leak0),
    .io_axi_r_ready_leak0              (io_axi_r_ready_leak0),
    .io_axi_b_ready_leak0              (io_axi_b_ready_leak0),
    .io_axi_arw_payload_addr_leak0     (io_axi_arw_payload_addr_leak0),
    .io_axi_w_payload_data_leak0       (io_axi_w_payload_data_leak0),
    .io_axi_arw_payload_write_leak0    (io_axi_arw_payload_write_leak0),
    .io_axi_arw_payload_burst_leak0    (io_axi_arw_payload_burst_leak0),
    .io_axi_arw_payload_id_leak0       (io_axi_arw_payload_id_leak0),
    .io_axi_arw_payload_len_leak0      (io_axi_arw_payload_len_leak0),
    .io_axi_arw_payload_size_leak0     (io_axi_arw_payload_size_leak0),
    .io_axi_arw_valid_leak0            (io_axi_arw_valid_leak0),
    .io_axi_w_payload_last_leak0       (io_axi_w_payload_last_leak0),
    .io_axi_w_payload_strb_leak0       (io_axi_w_payload_strb_leak0),
    .io_axi_w_valid_leak0              (io_axi_w_valid_leak0),

    // _leak0 ports — AXI taint interface
    .io_axi_arw_payload_addr_t0_leak0  (io_axi_arw_payload_addr_t0_leak0),
    .io_axi_arw_payload_burst_t0_leak0 (io_axi_arw_payload_burst_t0_leak0),
    .io_axi_arw_payload_id_t0_leak0    (io_axi_arw_payload_id_t0_leak0),
    .io_axi_arw_payload_len_t0_leak0   (io_axi_arw_payload_len_t0_leak0),
    .io_axi_arw_payload_size_t0_leak0  (io_axi_arw_payload_size_t0_leak0),
    .io_axi_arw_payload_write_t0_leak0 (io_axi_arw_payload_write_t0_leak0),
    .io_axi_arw_valid_t0_leak0         (io_axi_arw_valid_t0_leak0),
    .io_axi_b_ready_t0_leak0           (io_axi_b_ready_t0_leak0),
    .io_axi_r_ready_t0_leak0           (io_axi_r_ready_t0_leak0),
    .io_axi_w_payload_data_t0_leak0    (io_axi_w_payload_data_t0_leak0),
    .io_axi_w_payload_last_t0_leak0    (io_axi_w_payload_last_t0_leak0),
    .io_axi_w_payload_strb_t0_leak0    (io_axi_w_payload_strb_t0_leak0),
    .io_axi_w_valid_t0_leak0           (io_axi_w_valid_t0_leak0),

    // _leak0 ports — Peripherals
    .io_byteDev_rdata_ready_leak0      (io_byteDev_rdata_ready_leak0),
    .io_byteDev_wdata_payload_leak0    (io_byteDev_wdata_payload_leak0),
    .io_byteDev_wdata_valid_leak0      (io_byteDev_wdata_valid_leak0),
    .io_charOut_payload_leak0          (io_charOut_payload_leak0),
    .io_charOut_valid_leak0            (io_charOut_valid_leak0),
    .io_testDev_payload_leak0          (io_testDev_payload_leak0),
    .io_testDev_valid_leak0            (io_testDev_valid_leak0),

    // _leak0 ports — Peripheral taint
    .io_byteDev_rdata_ready_t0_leak0   (io_byteDev_rdata_ready_t0_leak0),
    .io_byteDev_wdata_payload_t0_leak0 (io_byteDev_wdata_payload_t0_leak0),
    .io_byteDev_wdata_valid_t0_leak0   (io_byteDev_wdata_valid_t0_leak0),
    .io_charOut_payload_t0_leak0       (io_charOut_payload_t0_leak0),
    .io_charOut_valid_t0_leak0         (io_charOut_valid_t0_leak0),
    .io_testDev_payload_t0_leak0       (io_testDev_payload_t0_leak0),
    .io_testDev_valid_t0_leak0         (io_testDev_valid_t0_leak0)

    // NOTE: The remaining ~60 internal _leak0 ports (pipeline_*, soc_*,
    // apb3Router_*, toplevel_*, io_apb_decoder_*, io_axi_arbiter_*)
    // are left unconnected. They are internal signals promoted to outputs
    // by CellIFT. The key IO-level leak signals above capture all
    // observable leakage. Verilator -Wno-PINCONNECTEMPTY suppresses
    // warnings for these.
  );

  // =========================================================================
  // AXI4 Memory Slave
  // =========================================================================
  //
  // Simple 1-cycle latency AXI4 memory slave matching Proteus sim/main.cpp.
  // Memory at base address 0x80000000 (word-addressed).
  // 128-bit AXI data bus = 4 x 32-bit words per beat.

  // SRAM read data (128-bit, matches AXI bus width)
  logic [127:0] sram_rdata;
  logic [127:0] sram_rdata_taint;

  // Generate 128-bit write mask from 16-byte strobe
  logic [127:0] sram_wmask;
  genvar gi;
  generate
    for (gi = 0; gi < 16; gi++) begin : gen_wmask
      assign sram_wmask[gi*8 +: 8] = {8{axi_w_payload_strb[gi]}};
    end
  endgenerate

  // SRAM storage with taint tracking
  ift_sram_mem #(
    .Width     (DataWidth),
    .Depth     (NumWords),
    .NumTaints (NumTaints)
  ) i_sram (
    .clk_i,
    .rst_ni,
    .req_i     (axi_arw_valid),
    .write_i   (axi_arw_valid & axi_arw_payload_write),
    .addr_i    (axi_arw_payload_addr[21:4]),  // 128-bit word address
    .wdata_i   (axi_w_payload_data),
    .wmask_i   (sram_wmask),
    .rdata_o   (sram_rdata),
    // Taint channels — connect Core's taint outputs to SRAM
    .req_i_taint   (axi_arw_valid_t0),
    .write_i_taint (axi_arw_payload_write_t0),
    .addr_i_taint  (axi_arw_payload_addr_t0[21:4]),  // 18-bit word address, matches addr_i
    .wdata_i_taint (axi_w_payload_data_t0),
    .wmask_i_taint ({128{1'b0}}),                     // keep zero to avoid is_mem_fully_tainted latch
    .rdata_o_taint (sram_rdata_taint)
  );

  // Simple AXI4 response logic
  assign axi_arw_ready = 1'b1;
  assign axi_w_ready   = 1'b1;

  // Read response (1 cycle latency)
  logic read_pending;
  logic [3:0] read_id;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      read_pending <= 1'b0;
      read_id <= 4'b0;
    end else begin
      read_pending <= axi_arw_valid & ~axi_arw_payload_write;
      read_id <= axi_arw_payload_id;
    end
  end

  assign axi_r_valid        = read_pending;
  assign axi_r_payload_data = sram_rdata;
  assign axi_r_payload_id   = read_id;
  assign axi_r_payload_resp = 2'b00;  // OKAY
  assign axi_r_payload_last = 1'b1;

  // Write response (immediate)
  assign axi_b_valid        = axi_arw_valid & axi_arw_payload_write;
  assign axi_b_payload_id   = axi_arw_payload_id;
  assign axi_b_payload_resp = 2'b00;  // OKAY

endmodule
