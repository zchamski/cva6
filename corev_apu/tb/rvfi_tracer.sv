// Copyright 2020 Thales DIS design services SAS
//
// Licensed under the Solderpad Hardware Licence, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0 WITH SHL-2.0
// You may obtain a copy of the License at https://solderpad.org/licenses/
//
// Original Author: Jean-Roch COULON (jean-roch.coulon@invia.fr)

// Import the DTM exit code setter function.
import "DPI-C" function void dtm_set_exitcode(input longint code);
import "DPI-C" function longint dtm_get_tohost_addr();

module rvfi_tracer #(
  parameter logic [7:0] HART_ID      = '0,
  parameter int unsigned DEBUG_START = 0,
  parameter int unsigned NR_COMMIT_PORTS = 2,
  parameter int unsigned DEBUG_STOP  = 0
)(
  input logic                           clk_i,
  input logic                           rst_ni,
  input rvfi_pkg::rvfi_instr_t[NR_COMMIT_PORTS-1:0]           rvfi_i
);

  logic[riscv::XLEN-1:0] TOHOST_ADDR;
  int f;
  int unsigned SIM_FINISH;

  initial begin
    f = $fopen($sformatf("trace_rvfi_hart_%h.dasm", HART_ID), "w");
    if (!$value$plusargs("time_out=%d", SIM_FINISH)) SIM_FINISH = 2000000;
  end

  final $fclose(f);

  logic [31:0] cycles;
  // Generate the trace based on RVFI
  logic [63:0] pc64;
  always_ff @(posedge clk_i) begin
    for (int i = 0; i < NR_COMMIT_PORTS; i++) begin
      pc64 = {{riscv::XLEN-riscv::VLEN{rvfi_i[i].pc_rdata[riscv::VLEN-1]}}, rvfi_i[i].pc_rdata};
      // print the instruction information if the instruction is valid or a trap is taken
      if (rvfi_i[i].valid) begin
        // Instruction information
        $fwrite(f, "core   0: 0x%h (0x%h) DASM(%h)\n",
          pc64, rvfi_i[i].insn, rvfi_i[i].insn);
        // Destination register information
        $fwrite(f, "%h 0x%h (0x%h)",
          rvfi_i[i].mode, pc64, rvfi_i[i].insn);
        // Decode instruction to know if destination register is FP register
        if ( rvfi_i[i].insn[6:0] == 7'b1001111 ||
             rvfi_i[i].insn[6:0] == 7'b1001011 ||
             rvfi_i[i].insn[6:0] == 7'b1000111 ||
             rvfi_i[i].insn[6:0] == 7'b1000011 ||
             rvfi_i[i].insn[6:0] == 7'b0000111 ||
            (rvfi_i[i].insn[6:0] == 7'b1010011 && rvfi_i[i].insn[31:26] != 6'b111000
                                               && rvfi_i[i].insn[31:26] != 6'b101000
                                               && rvfi_i[i].insn[31:26] != 6'b110000) )
          $fwrite(f, " f%d 0x%h\n",
            rvfi_i[i].rd_addr, rvfi_i[i].rd_wdata);
        else if (rvfi_i[i].rd_addr != 0) begin
          $fwrite(f, " x%d 0x%h\n",
            rvfi_i[i].rd_addr, rvfi_i[i].rd_wdata);
        end else $fwrite(f, "\n");
        // if (rvfi_i[i].insn == 32'h00000073) begin
        //   $finish(1);
        //   $finish(1);
        // end
        // TERMINATION in 64 bits: upon SD to TOHOST with bit 0 of MEM_WDATA == 1'b1
        // and the two MSBytes of MEM_WDATA equal to zero.
        // TOHOST is assumed aligned on a 64-bit boundary.
        // Treat first uncompressed insns.
        if (rvfi_i[i].insn[31:16] != '0 &&
            rvfi_i[i].insn[6:0]        == 7'b0100011  &&
            rvfi_i[i].insn[14:12]      == 3'b011      ) begin
          TOHOST_ADDR = dtm_get_tohost_addr();
          if (TOHOST_ADDR == '0) begin
            $display("*** No valid address of 'tohost' (tohost == 0x%h), termination possible only by timeout or Ctrl-C!\n", TOHOST_ADDR);
            $fwrite(f, "*** No valid address of 'tohost' (tohost == 0x%h), termination possible only by timeout or Ctrl-C!\n", TOHOST_ADDR);
          end

          $fwrite(f, "### Got SD, TOHOST_ADDR = 0x%h\n", TOHOST_ADDR);
        end

        if (rvfi_i[i].insn[31:16] == '0) begin // compressed instruction
          if (rvfi_i[i].insn[15:13] == 3'b111 &&
              rvfi_i[i].insn[1:0] == 2'b00) begin
            $fwrite(f, "### Got a *compressed* SD instruction, TOHOST_ADDR = 0x%h\n", TOHOST_ADDR);
          end
        end

        $fwrite(f, "###    mem_addr  = 0x%h\n", rvfi_i[i].mem_addr);
        $fwrite(f, "###    mem_wmask = 0x%h\n", rvfi_i[i].mem_wmask);
        $fwrite(f, "###    mem_wdata = 0x%h\n", rvfi_i[i].mem_wdata);
        $fwrite(f, "###    mem_rmask = 0x%h\n", rvfi_i[i].mem_rmask);
        $fwrite(f, "###    mem_rdata = 0x%h\n", rvfi_i[i].mem_rdata);

        if (rvfi_i[i].mem_addr       == TOHOST_ADDR) begin
          $fwrite(f, "### Got SD to TOHOST_ADDR (0x%h)\n", TOHOST_ADDR);
          if (rvfi_i[i].mem_wdata[63:48] == '0 &&
              rvfi_i[i].mem_wdata[0]     == 0'b1) begin
            dtm_set_exitcode(rvfi_i[i].mem_wdata);
            $finish(1);
            $finish(1);
          end
        end
      end else if (rvfi_i[i].trap)
        $fwrite(f, "exception : 0x%h\n", pc64);
    end
    if (cycles > SIM_FINISH) $finish(1);
  end

  always_ff @(posedge clk_i or negedge rst_ni)
    if (~rst_ni)
      cycles <= 0;
    else
      cycles <= cycles+1;

  // Trace any custom signals
  // Define signals to be traced by adding them into debug and name arrays
  string name[0:10];
  logic[63:0] debug[0:10], debug_previous[0:10];

  always_ff @(posedge clk_i) begin
    if (cycles > DEBUG_START && cycles < DEBUG_STOP)
      for (int index = 0; index < 100; index++)
        if (debug_previous[index] != debug[index])
          $fwrite(f, "%d %s %x\n", cycles, name[index], debug[index]);
    debug_previous <= debug;
  end

endmodule // rvfi_tracer
