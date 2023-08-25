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
import rvfi_pkg::*;

`include "uvm_macros.svh"
import "DPI-C" function int spike_create(string filename);

import "DPI-C" function void spike_set_param_uint64_t(string base, string name, longint unsigned value);
import "DPI-C" function void spike_set_param_str(string base, string name, string value);
import "DPI-C" function void spike_set_default_params(string profile);

import "DPI-C" function void spike_step(output st_rvfi rvfi);

module spike #(
  parameter config_pkg::cva6_cfg_t CVA6Cfg = config_pkg::cva6_cfg_default,
  parameter type rvfi_instr_t = struct packed {
    logic [config_pkg::NRET-1:0]                  valid;
    logic [config_pkg::NRET*64-1:0]               order;
    logic [config_pkg::NRET*config_pkg::ILEN-1:0] insn;
    logic [config_pkg::NRET-1:0]                  trap;
    logic [config_pkg::NRET*riscv::XLEN-1:0]      cause;
    logic [config_pkg::NRET-1:0]                  halt;
    logic [config_pkg::NRET-1:0]                  intr;
    logic [config_pkg::NRET*2-1:0]                mode;
    logic [config_pkg::NRET*2-1:0]                ixl;
    logic [config_pkg::NRET*5-1:0]                rs1_addr;
    logic [config_pkg::NRET*5-1:0]                rs2_addr;
    logic [config_pkg::NRET*riscv::XLEN-1:0]      rs1_rdata;
    logic [config_pkg::NRET*riscv::XLEN-1:0]      rs2_rdata;
    logic [config_pkg::NRET*5-1:0]                rd_addr;
    logic [config_pkg::NRET*riscv::XLEN-1:0]      rd_wdata;
    logic [config_pkg::NRET*riscv::XLEN-1:0]      pc_rdata;
    logic [config_pkg::NRET*riscv::XLEN-1:0]      pc_wdata;
    logic [config_pkg::NRET*riscv::VLEN-1:0]      mem_addr;
    logic [config_pkg::NRET*riscv::PLEN-1:0]      mem_paddr;
    logic [config_pkg::NRET*(riscv::XLEN/8)-1:0]  mem_rmask;
    logic [config_pkg::NRET*(riscv::XLEN/8)-1:0]  mem_wmask;
    logic [config_pkg::NRET*riscv::XLEN-1:0]      mem_rdata;
    logic [config_pkg::NRET*riscv::XLEN-1:0]      mem_wdata;
  },
  parameter longint unsigned DramBase = 'h8000_0000,
  parameter int unsigned     Size     = 64 * 1024 * 1024 // 64 Mega Byte
)(
    input logic                                     clk_i,
    input logic                                     rst_ni,
    input logic                                     clint_tick_i,
    input rvfi_instr_t[CVA6Cfg.NrCommitPorts:1-0]   rvfi_i
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
                            CVA6Cfg.RVA ? "A" : "",
                            CVA6Cfg.RVF ? "F" : "",
                            CVA6Cfg.RVD ? "D" : "",
                            CVA6Cfg.RVC ? "C" : "");
        // TODO Fixme
        //if (CVA6Cfg.CVA6ConfigBExtEn) begin
        //    rtl_isa = $sformatf("%s_zba_zbb_zbc_zbs", rtl_isa);
        //end
        // TODO: build the ISA string with extensions
       void'(spike_set_default_params("cva6"));
       void'(spike_set_param_uint64_t("/top/core/0/", "boot_addr", 'h10000));
       void'(spike_set_param_str("/top/", "isa", rtl_isa));
       void'(spike_set_param_str("/top/core/0/", "isa", rtl_isa));
       void'(spike_create(binary));

    end

    st_rvfi rvfi;
    logic [63:0] pc64;
    logic [31:0] rtl_instr;
    logic [31:0] spike_instr;
    string       cause;
    const string format_instr_str  = "%15s | RVFI | %8d | %6d | %8x | %8x | %x | x%-8x | %-8x | x%-16x | %-16x | x%-8x | %-8x";
    string instr;

    always_ff @(posedge clk_i) begin
        if (rst_ni) begin

            for (int i = 0; i < CVA6Cfg.NrCommitPorts; i++) begin
                pc64 = {{riscv::XLEN-riscv::VLEN{rvfi_i[i].pc_rdata[riscv::VLEN-1]}}, rvfi_i[i].pc_rdata};

                if (rvfi_i[i].trap) begin
`ifdef SPIKE_MISSING_DATA
                       assert (rvfi.trap === rvfi_i[i].trap) else begin
                          $warning("\x1B[38;5;221m[Tandem] Exception not detected\x1B[0m");
                          $display("\x1B[91mCVA6:  %p\x1B[0m", rvfi_i[i].trap);
                          $display("\x1B[91mSpike: %p\x1B[0m", rvfi.trap);
                          $finish;
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
                       spike_step(rvfi);
                    end
                if (rvfi_i[i].valid) begin
                    spike_step(rvfi);
                    spike_instr = (rvfi.insn[1:0] != 2'b11) ? {16'b0, rvfi.insn[15:0]} : rvfi.insn;
                    rtl_instr = rvfi_i[i].insn;
                    // $display("[Spike Tandem] commit_log = %p", commit_log);
                    // $display("\x1B[32mSpike: PC = 0x%h, instr = 0x%h\x1B[0m", commit_log.pc, spike_instr);
                    // $display("\x1B[91mCVA6:  PC = 0x%h, instr = 0x%h\x1B[0m", pc64, rtl_instr);
                    assert (rvfi.pc_rdata === pc64) else begin
                        $warning("\x1B[38;5;221m[Tandem] PC Mismatch\x1B[0m");
                        $display("\x1B[91mSpike: 0x%16h\x1B[0m", rvfi.pc_rdata);
                        $display("\x1B[91mCVA6:  0x%16h\x1B[0m", pc64);
                        $finish;
                    end
                    if (!rvfi_i[i].trap) begin
                        assert (rvfi.mode === rvfi_i[i].mode) else begin
                            $warning("\x1B[38;5;221m[Tandem] Privilege level mismatch\x1B[0m");
                            $display("\x1B[91mSpike: %2d @ PC 0x%16h\x1B[0m", rvfi.mode, rvfi.pc_rdata);
                            $display("\x1B[91mCVA6:  %2d @ PC 0x%16h\x1B[0m", rvfi_i[i].mode, pc64);
                             $finish;
                        end

                        assert (spike_instr === rtl_instr) else begin
                            $warning("\x1B[38;5;221m[Tandem] Decoded instruction mismatch\x1B[0m");
                            $display("\x1B[91m0x%h != 0x%h @ PC 0x%h\x1B[0m", rtl_instr, spike_instr, rvfi.pc_rdata);
                            $finish;
                        end

                        // TODO(zarubaf): Adapt for floating point instructions
                        if (rvfi_i[i].rd_addr != 0) begin
                            // check the return value
                            // $display("\x1B[37m%h === %h\x1B[0m", commit_instr_i[i].rd, commit_log.rd);
                            assert (rvfi_i[i].rd_addr[4:0] === rvfi.rd1_addr[4:0]) else begin
                                $warning("\x1B[38;5;221m[Tandem] Destination register mismatch\x1B[0m");
                                $display("\x1B[91mSpike: x%-4d @ PC 0x%16h\x1B[0m",
                                         rvfi.rd1_addr[4:0], rvfi.pc_rdata);
                                $display("\x1B[91mCVA6:  x%-4d @ PC 0x%16h\x1B[0m",
                                         rvfi_i[i].rd_addr[4:0], pc64);
                                $finish;
                            end
                            assert (rvfi_i[i].rd_wdata === rvfi.rd1_wdata) else begin
                                $warning("\x1B[38;5;221m[Tandem] Write back data mismatch\x1B[0m");
                                $display("\x1B[91mSpike: x%-4d <- 0x%16h @ PC 0x%16h\x1B[0m",
                                         rvfi.rd1_wdata[4:0], rvfi.rd1_wdata, rvfi.pc_rdata);
                                $display("\x1B[91mCVA6:  x%-4d <- 0x%16h @ PC 0x%16h\x1B[0m",
                                         rvfi_i[i].rd_addr[4:0], rvfi_i[i].rd_wdata, pc64);
                                $finish;
                            end
                        end
                    end

                    instr = $sformatf(format_instr_str, $sformatf("%t", $time),
                                        rvfi.cycle_cnt,
                                        rvfi.order,
                                        rvfi.pc_rdata,
                                        rvfi.insn,
                                        rvfi.mode,
                                        rvfi.rs1_addr, rvfi.rs1_rdata,
                                        rvfi.rs2_addr, rvfi.rs2_rdata,
                                        rvfi.rd1_addr, rvfi.rd1_wdata);
                    $display(instr);
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
        //if (rst_ni) begin
        //    void'(clint_tick());
        //end
    end
endmodule
