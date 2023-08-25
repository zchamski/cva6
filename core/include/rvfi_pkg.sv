`ifndef __UVMA_RVFI_TDEFS_SV__
`define __UVMA_RVFI_TDEFS_SV__

package rvfi_pkg;

typedef struct {
   longint unsigned         nret_id;
   longint unsigned         cycle_cnt;
   longint unsigned         order;
   longint unsigned         insn;
   byte unsigned            trap;
   byte unsigned            halt;
   byte unsigned            intr;
   int unsigned             mode;
   int unsigned             ixl;
   int unsigned             dbg;
   int unsigned             dbg_mode;
   longint unsigned         nmip;

   longint unsigned         insn_interrupt;
   longint unsigned         insn_interrupt_id;
   longint unsigned         insn_bus_fault;
   longint unsigned         insn_nmi_store_fault;
   longint unsigned         insn_nmi_load_fault;

   longint unsigned         pc_rdata;
   longint unsigned         pc_wdata;

   longint unsigned         rs1_addr;
   longint unsigned         rs1_rdata;

   longint unsigned         rs2_addr;
   longint unsigned         rs2_rdata;

   longint unsigned         rs3_addr;
   longint unsigned         rs3_rdata;

   longint unsigned         rd1_addr;
   longint unsigned         rd1_wdata;

   longint unsigned         rd2_addr;
   longint unsigned         rd2_wdata;

   longint unsigned         mem_addr;
   longint unsigned         mem_rdata;
   longint unsigned         mem_rmask;
   longint unsigned         mem_wdata;
   longint unsigned         mem_wmask;

} st_rvfi;
endpackage

`endif
