// Proteus Dynamic OoO Core - Vanilla (non-CellIFT) Wrapper
//
// Wraps the uninstrumented Proteus Core with an AXI4 memory slave.
// No taint tracking or leakage counters.

module proteus_tiny_soc #(
    parameter int unsigned NumWords = 1 << 18, // 256K x 128-bit = 4MB
    parameter int unsigned DataWidth = 128
) (
  input logic clk_i,
  input logic rst_ni
);

  // AXI4 Shared Bus Signals
  logic        axi_arw_valid;
  logic        axi_arw_ready;
  logic [29:0] axi_arw_payload_addr;
  logic [3:0]  axi_arw_payload_id;
  logic [7:0]  axi_arw_payload_len;
  logic [2:0]  axi_arw_payload_size;
  logic [1:0]  axi_arw_payload_burst;
  logic        axi_arw_payload_write;

  logic         axi_w_valid;
  logic         axi_w_ready;
  logic [127:0] axi_w_payload_data;
  logic [15:0]  axi_w_payload_strb;
  logic         axi_w_payload_last;

  logic        axi_b_valid;
  logic        axi_b_ready;
  logic [3:0]  axi_b_payload_id;
  logic [1:0]  axi_b_payload_resp;

  logic         axi_r_valid;
  logic         axi_r_ready;
  logic [127:0] axi_r_payload_data;
  logic [3:0]   axi_r_payload_id;
  logic [1:0]   axi_r_payload_resp;
  logic         axi_r_payload_last;

  // Peripheral signals
  logic        charOut_valid;
  logic [7:0]  charOut_payload;
  logic        testDev_valid;
  logic [31:0] testDev_payload;
  logic        byteDev_wdata_valid;
  logic [7:0]  byteDev_wdata_payload;
  logic        byteDev_rdata_ready;

  // Core instantiation (vanilla — no _t0 or _leak0 ports)
  Core i_core (
    .clk     (clk_i),
    .reset   (~rst_ni),

    .io_axi_arw_valid          (axi_arw_valid),
    .io_axi_arw_ready          (axi_arw_ready),
    .io_axi_arw_payload_addr   (axi_arw_payload_addr),
    .io_axi_arw_payload_id     (axi_arw_payload_id),
    .io_axi_arw_payload_len    (axi_arw_payload_len),
    .io_axi_arw_payload_size   (axi_arw_payload_size),
    .io_axi_arw_payload_burst  (axi_arw_payload_burst),
    .io_axi_arw_payload_write  (axi_arw_payload_write),
    .io_axi_w_valid            (axi_w_valid),
    .io_axi_w_ready            (axi_w_ready),
    .io_axi_w_payload_data     (axi_w_payload_data),
    .io_axi_w_payload_strb     (axi_w_payload_strb),
    .io_axi_w_payload_last     (axi_w_payload_last),
    .io_axi_b_valid            (axi_b_valid),
    .io_axi_b_ready            (axi_b_ready),
    .io_axi_b_payload_id       (axi_b_payload_id),
    .io_axi_b_payload_resp     (axi_b_payload_resp),
    .io_axi_r_valid            (axi_r_valid),
    .io_axi_r_ready            (axi_r_ready),
    .io_axi_r_payload_data     (axi_r_payload_data),
    .io_axi_r_payload_id       (axi_r_payload_id),
    .io_axi_r_payload_resp     (axi_r_payload_resp),
    .io_axi_r_payload_last     (axi_r_payload_last),

    .io_charOut_valid           (charOut_valid),
    .io_charOut_payload         (charOut_payload),
    .io_testDev_valid           (testDev_valid),
    .io_testDev_payload         (testDev_payload),
    .io_byteDev_wdata_valid     (byteDev_wdata_valid),
    .io_byteDev_wdata_payload   (byteDev_wdata_payload),
    .io_byteDev_rdata_valid     (1'b0),
    .io_byteDev_rdata_payload   (8'b0),
    .io_byteDev_rdata_ready     (byteDev_rdata_ready)
  );

  // SRAM read data (128-bit, matches AXI bus width)
  logic [127:0] sram_rdata;

  // Generate 128-bit write mask from 16-byte strobe
  logic [127:0] sram_wmask;
  genvar gi;
  generate
    for (gi = 0; gi < 16; gi++) begin : gen_wmask
      assign sram_wmask[gi*8 +: 8] = {8{axi_w_payload_strb[gi]}};
    end
  endgenerate

  // SRAM (no taint tracking in vanilla mode)
  noift_sram_mem #(
    .Width (DataWidth),
    .Depth (NumWords)
  ) i_sram (
    .clk_i,
    .rst_ni,
    .req_i     (axi_arw_valid),
    .write_i   (axi_arw_valid & axi_arw_payload_write),
    .addr_i    (axi_arw_payload_addr[21:4]),
    .wdata_i   (axi_w_payload_data),
    .wmask_i   (sram_wmask),
    .rdata_o   (sram_rdata)
  );

  // AXI response logic
  assign axi_arw_ready = 1'b1;
  assign axi_w_ready   = 1'b1;

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
  assign axi_r_payload_resp = 2'b00;
  assign axi_r_payload_last = 1'b1;

  assign axi_b_valid        = axi_arw_valid & axi_arw_payload_write;
  assign axi_b_payload_id   = axi_arw_payload_id;
  assign axi_b_payload_resp = 2'b00;

endmodule
