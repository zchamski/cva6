// Copyright 2018 ETH Zurich and University of Bologna.
// Copyright and related rights are licensed under the Solderpad Hardware
// License, Version 0.51 (the "License"); you may not use this file except in
// compliance with the License.  You may obtain a copy of the License at
// http://solderpad.org/licenses/SHL-0.51. Unless required by applicable law
// or agreed to in writing, software, hardware and materials distributed under
// this License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// Author: Florian Zaruba, ETH Zurich
// Date: 3/11/2018
// Description: Wrapped Spike Model for Tandem Verification

import uvm_pkg::*;

`include "uvm_macros.svh"

import "DPI-C" function int spike_create(string filename, longint unsigned dram_base, int unsigned size);

typedef riscv::commit_log_t riscv_commit_log_t;
import "DPI-C" function void spike_tick(output riscv_commit_log_t commit_log);

import "DPI-C" function void clint_tick();

module spike #(
    parameter longint unsigned DramBase = 'h8000_0000,
    parameter int unsigned     Size     = 64 * 1024 * 1024 // 64 Mega Byte
)(
    input logic       clk_i,
    input logic       rst_ni,
    input logic       clint_tick_i,
    input ariane_pkg::rvfi_port_t  rvfi_i
);
    static uvm_cmdline_processor uvcl = uvm_cmdline_processor::get_inst();

    string binary = "";

    logic fake_clk;

    logic clint_tick_q, clint_tick_qq, clint_tick_qqq, clint_tick_qqqq;

    initial begin
        `uvm_info("Spike Tandem", "Setting up Spike...", UVM_NONE);
        void'(uvcl.get_arg_value("+PRELOAD=", binary));
        assert(binary != "") else $error("We need a preloaded binary for tandem verification");
        void'(spike_create(binary, DramBase, Size));
    end

    riscv_commit_log_t commit_log;
    logic [63:0] pc64;
    logic [31:0] rtl_instr;
    logic [31:0] spike_instr;

    always_ff @(posedge clk_i) begin
        if (rst_ni) begin

            for (int i = 0; i < ariane_pkg::NR_COMMIT_PORTS; i++) begin
                if (rvfi_i[i].valid) begin
                    spike_tick(commit_log);
`ifdef SPIKE_MISSING_DATA
                    spike_instr = (commit_log.instr[1:0] != 2'b11) ? {16'b0, commit_log.instr[15:0]} : commit_log.instr;
`endif
                    rtl_instr = rvfi_i[i].insn;
                    pc64 = {{riscv::XLEN-riscv::VLEN{rvfi_i[i].pc_rdata[riscv::VLEN-1]}}, rvfi_i[i].pc_rdata};
`ifdef SPIKE_MISSING_DATA
                    $display("\x1B[32m%h %h\x1B[0m", commit_log.pc, spike_instr);
`endif
                    $display("%p", commit_log);

                    $display("\x1B[91mCVA6: PC = %h, instr = %h\x1B[0m", pc64, rtl_instr);
                    assert (commit_log.pc === pc64) else begin
                        $warning("\x1B[38;5;221m[Tandem] PC Mismatch\x1B[0m");
                        // $stop;
                        $display("\x1B[91mSpike: %16h\x1B[0m", commit_log.pc);
                        $display("\x1B[91mCVA6:  %16h\x1B[0m", pc64);
                    end
`ifdef SPIKE_MISSING_DATA
                    assert (commit_log.was_exception === rvfi_i[i].trap) else begin
                        $warning("\x1B[38;5;221m[Tandem] Exception not detected\x1B[0m");
                        // $stop;
                        $display("\x1B[91mSpike: %p\x1B[0m", commit_log.was_exception);
                        $display("\x1B[91mCVA6:  %p\x1B[0m", rvfi_i[i].trap);
                    end
`endif
                    if (!rvfi_i[i].trap) begin
                        assert (commit_log.priv === rvfi_i[i].mode) else begin
                            $warning("\x1B[38;5;221m[Tandem] Privilege level mismatch\x1B[0m");
                            // $stop;
                            $display("\x1B[91mSpike: %2d @ PC %16h\x1B[0m", commit_log.priv, commit_log.pc);
                            $display("\x1B[91mCVA6:  %2d @ PC %16h\x1B[0m", rvfi_i[i].mode, pc64);
                        end
`ifdef SPIKE_MISSING_DATA
                        assert (spike_instr === rtl_instr) else begin
                            $warning("\x1B[38;5;221m[Tandem] Decoded instructions mismatch\x1B[0m");
                            // $stop;
                            $display("\x1B[91m%h === %h @ PC %h\x1B[0m", rtl_instr, spike_instr, commit_log.pc);
                        end
`endif
                        // TODO(zarubaf): Adapt for floating point instructions
                        if (rvfi_i[i].rd_addr != 0) begin
                            // check the return value
                            // $display("\x1B[37m%h === %h\x1B[0m", commit_instr_i[i].rd, commit_log.rd);
                            assert (rvfi_i[i].rd_addr === commit_log.rd) else begin
                                $warning("\x1B[38;5;221m[Tandem] Destination register mismatch\x1B[0m");
                                $display("\x1B[91mSpike: x%d @ PC %16h\x1B[0m", commit_log.rd, commit_log.pc);
                                $display("\x1B[91mCVA6:  x%d @ PC %16h\x1B[0m", rvfi_i[i].rd_addr, pc64);
                                // $stop;
                            end
                            assert (rvfi_i[i].rd_wdata === commit_log.data) else begin
                                $warning("\x1B[38;5;221m[Tandem] Write back data mismatch\x1B[0m");
                                $display("\x1B[91mSpike: %16h @ PC %16h\x1B[0m", commit_log.data, commit_log.pc);
                                $display("\x1B[91mCVA6:  %16h @ PC %16h\x1B[0m", rvfi_i[i].rd_wdata, pc64);
                            end
                        end
                    end
                end
            end
        end
    end

    // we want to schedule the timer increment at the end of this cycle
    assign #1ps fake_clk = clk_i;

    always_ff @(posedge fake_clk) begin
        clint_tick_q <= clint_tick_i;
        clint_tick_qq <= clint_tick_q;
        clint_tick_qqq <= clint_tick_qq;
        clint_tick_qqqq <= clint_tick_qqq;
    end

    always_ff @(posedge clint_tick_qqqq) begin
        if (rst_ni) begin
            void'(clint_tick());
        end
    end
endmodule
