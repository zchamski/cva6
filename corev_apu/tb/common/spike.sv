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

import ariane_pkg::*;
import uvm_pkg::*;

`include "uvm_macros.svh"

import "DPI-C" function int spike_create(string filename, string rtl_isa, longint unsigned dram_base, int unsigned size);

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
    string rtl_isa = "";

    logic fake_clk;
    logic clint_tick_q, clint_tick_qq, clint_tick_qqq, clint_tick_qqqq;

    initial begin
        `uvm_info("Spike Tandem", "Setting up Spike...", UVM_NONE);
        void'(uvcl.get_arg_value("+PRELOAD=", binary));
        assert(binary != "") else $error("We need a preloaded binary for tandem verification");
        // ISA string format: RV<XLEN>IM?A?C?F?D?C?(_<ext>)* (FORNOW no RV64GC)
        // Base string
        rtl_isa = $sformatf("RV%-2dIM%s%s%s%s",
                            riscv::XLEN,
                            ariane_pkg::RVA ? "A" : "",
                            ariane_pkg::RVF ? "F" : "",
                            ariane_pkg::RVD ? "D" : "",
                            ariane_pkg::RVC ? "C" : "");
        if (ariane_pkg::BITMANIP) begin
            rtl_isa = $sformatf("%s_zba_zbb_zbc_zbs", rtl_isa);
        end
        // TODO: build the ISA string with extensions
        void'(spike_create(binary, rtl_isa, DramBase, Size));
    end

    riscv_commit_log_t commit_log;
    logic [63:0] pc64;
    logic [31:0] rtl_instr;
    logic [31:0] spike_instr;
    string       cause;

    always_ff @(posedge clk_i) begin
        if (rst_ni) begin

            for (int i = 0; i < ariane_pkg::NR_COMMIT_PORTS; i++) begin
                pc64 = {{riscv::XLEN-riscv::VLEN{rvfi_i[i].pc_rdata[riscv::VLEN-1]}}, rvfi_i[i].pc_rdata};

                if (rvfi_i[i].trap) begin
`ifdef SPIKE_MISSING_DATA
                       assert (commit_log.was_exception === rvfi_i[i].trap) else begin
                          $warning("\x1B[38;5;221m[Tandem] Exception not detected\x1B[0m");
                          // $stop;
                          $display("\x1B[91mSpike: %p\x1B[0m", commit_log.was_exception);
                          $display("\x1B[91mCVA6:  %p\x1B[0m", rvfi_i[i].trap);
                       end
`endif
                       case (rvfi_i[i].cause)
			 32'h0 : cause = "INSTR_ADDR_MISALIGNED";
			 32'h1 : cause = "INSTR_ACCESS_FAULT";
			 32'h2 : cause = "ILLEGAL_INSTR";
			 32'h3 : cause = "BREAKPOINT";
			 32'h4 : cause = "LD_ADDR_MISALIGNED";
			 32'h5 : cause = "LD_ACCESS_FAULT";
			 32'h6 : cause = "ST_ADDR_MISALIGNED";
			 32'h7 : cause = "ST_ACCESS_FAULT";
			 32'h8 : cause = "USER_ECALL";
			 32'h9 : cause = "SUPERVISOR_ECALL";
			 32'ha : cause = "VIRTUAL_SUPERVISOR_ECALL";
			 32'hb : cause = "MACHINE_ECALL";
			 32'hc : cause = "FETCH_PAGE_FAULT";
			 32'hd : cause = "LOAD_PAGE_FAULT";
			 32'hf : cause = "STORE_PAGE_FAULT";
			 32'h14: cause = "FETCH_GUEST_PAGE_FAULT";
			 32'h15: cause = "LOAD_GUEST_PAGE_FAULT";
			 32'h16: cause = "VIRTUAL_INSTRUCTION";
			 32'h17: cause = "STORE_GUEST_PAGE_FAULT";
			 default: $error("[Spike Tandem] *** Unhandled trap ID %d (0x%h)\n",
					 rvfi_i[i].cause, rvfi_i[i].cause);
                       endcase;

                       $display("\x1B[91mCVA6 exception %s at 0x%h\n", cause, pc64);
                       spike_tick(commit_log);
                    end
                if (rvfi_i[i].valid) begin
                    spike_tick(commit_log);
                    spike_instr = (commit_log.instr[1:0] != 2'b11) ? {16'b0, commit_log.instr[15:0]} : commit_log.instr;
                    rtl_instr = rvfi_i[i].insn;
                    // $display("[Spike Tandem] commit_log = %p", commit_log);
                    // $display("\x1B[32mSpike: PC = 0x%h, instr = 0x%h\x1B[0m", commit_log.pc, spike_instr);
                    // $display("\x1B[91mCVA6:  PC = 0x%h, instr = 0x%h\x1B[0m", pc64, rtl_instr);
                    assert (commit_log.pc === pc64) else begin
                        $warning("\x1B[38;5;221m[Tandem] PC Mismatch\x1B[0m");
                        // $stop;
                        $display("\x1B[91mSpike: 0x%16h\x1B[0m", commit_log.pc);
                        $display("\x1B[91mCVA6:  0x%16h\x1B[0m", pc64);
                    end
                    if (!rvfi_i[i].trap) begin
                        assert (commit_log.priv === rvfi_i[i].mode) else begin
                            $warning("\x1B[38;5;221m[Tandem] Privilege level mismatch\x1B[0m");
                            // $stop;
                            $display("\x1B[91mSpike: %2d @ PC 0x%16h\x1B[0m", commit_log.priv, commit_log.pc);
                            $display("\x1B[91mCVA6:  %2d @ PC 0x%16h\x1B[0m", rvfi_i[i].mode, pc64);
                        end

                        assert (spike_instr === rtl_instr) else begin
                            $warning("\x1B[38;5;221m[Tandem] Decoded instruction mismatch\x1B[0m");
                            // $stop;
                            $display("\x1B[91m0x%h != 0x%h @ PC 0x%h\x1B[0m", rtl_instr, spike_instr, commit_log.pc);
                        end

                        // TODO(zarubaf): Adapt for floating point instructions
                        if (rvfi_i[i].rd_addr != 0) begin
                            // check the return value
                            // $display("\x1B[37m%h === %h\x1B[0m", commit_instr_i[i].rd, commit_log.rd);
                            assert (rvfi_i[i].rd_addr[4:0] === commit_log.rd[4:0]) else begin
                                $warning("\x1B[38;5;221m[Tandem] Destination register mismatch\x1B[0m");
                                $display("\x1B[91mSpike: x%-4d @ PC 0x%16h\x1B[0m",
                                         commit_log.rd[4:0], commit_log.pc);
                                $display("\x1B[91mCVA6:  x%-4d @ PC 0x%16h\x1B[0m",
                                         rvfi_i[i].rd_addr[4:0], pc64);
                                // $stop;
                            end
                            assert (rvfi_i[i].rd_wdata === commit_log.data) else begin
                                $warning("\x1B[38;5;221m[Tandem] Write back data mismatch\x1B[0m");
                                $display("\x1B[91mSpike: x%-4d <- 0x%16h @ PC 0x%16h\x1B[0m",
                                         commit_log.rd[4:0], commit_log.data, commit_log.pc);
                                $display("\x1B[91mCVA6:  x%-4d <- 0x%16h @ PC 0x%16h\x1B[0m",
                                         rvfi_i[i].rd_addr[4:0], rvfi_i[i].rd_wdata, pc64);
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
