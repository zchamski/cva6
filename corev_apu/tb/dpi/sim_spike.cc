// See LICENSE for license details.

#include "sim_spike.h"
#include "mmu.h"
#include <map>
#include <iostream>
#include <sstream>
#include <climits>
#include <cstdlib>
#include <cassert>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>

std::vector<std::pair<reg_t, abstract_device_t*>> plugin_devs;

// FIXME TODO Review settings of dm_config below.
debug_module_config_t dm_config = {
  .progbufsize = 2,
  .max_sba_data_width = 0,
  .require_authentication = false,
  .abstract_rti = 0,
  .support_hasel = true,
  .support_abstract_csr_access = true,
  .support_abstract_fpr_access = true,
  .support_haltgroups = true,
  .support_impebreak = true
};

sim_spike_t::sim_spike_t(const cfg_t *cfg,
             std::vector<std::pair<reg_t, mem_t*>> mems,
             const std::vector<std::string>& args,
             size_t max_steps)
  : sim_t(cfg,   // cfg
          false,  // halted
          mems,  // mems
          plugin_devs,
          args,
          dm_config,
          "tandem.log",  // log_path
          true, // dtb_enabled
          nullptr,  // dtb_file
          false, // socket_enabled
          NULL,  // cmd_file
          max_steps)
{
  get_core(0)->enable_log_commits();
  get_core(0)->get_state()->pc = 0x10000;
  // It seems mandatory to set cache block size for MMU.
  // FIXME TODO: Use actual cache configuration (on/off, # of ways/sets).
  // FIXME TODO: Support multiple cores.
  get_core(0)->get_mmu()->set_cache_blocksz(reg_t(64));
  std::cerr << "[Spike Tandem] Simulator instantiated.\n";
}

sim_spike_t::~sim_spike_t()
{
}

commit_log_t sim_spike_t::tick(size_t n)
{
  commit_log_t commit_log;

  // The state PC is the *next* insn fetch address.
  // Catch it before exec which yields a new value.
  reg_t pc = get_core(0)->get_state()->pc;

  // execute instruction
  get_core(0)->step(n);
  // std::cerr << "[Spike Tandem] current PC = 0x" << std::hex << pc << "\n";
  // std::cerr << "[Spike Tandem] next PC    = 0x" << std::hex << get_core(0)->get_state()->pc << "\n";

  // TODO FIXME Handle multiple/zero writes in a single insn.
  auto& reg_commits = get_core(0)->get_state()->log_reg_write;
  int priv = get_core(0)->get_state()->last_inst_priv;
  int xlen = get_core(0)->get_state()->last_inst_xlen;
  int flen = get_core(0)->get_state()->last_inst_flen;
  commit_log.instr = (uint32_t) (get_core(0)->get_state()->last_inst_fetched & 0xffffffffULL);

  commit_log.priv = priv;
  commit_log.pc = pc;
  bool got_commit = false;
  // std::cerr << "[Spike Tandem] reg_commits.len() = " << std::dec << reg_commits.size() << "\n";
  for (auto& reg : reg_commits) {
    // std::cerr << "[Spike Tandem] reg.first = 0x" << std::hex << reg.first << "\n";
    // std::cerr << "[Spike Tandem] reg.second.v[0] = 0x" << std::hex << reg.second.v[0] << "\n";
    // std::cerr << "[Spike Tandem] reg.second.v[1] = 0x" << std::hex << reg.second.v[1] << "\n";

    if (!got_commit) {
      commit_log.is_fp = reg.first & 0xf == 1;
      commit_log.rd = reg.first >> 4;
      // TODO FIXME Take into account the XLEN/FLEN for int/FP values.
      commit_log.data = reg.second.v[0];
      // TODO FIXME Handle multiple register commits per cycle.
      // TODO FIXME This must be handled on the RVFI side as well.
      got_commit = true; // FORNOW Latch only the first commit.
    }
  }

  // Remove sign extension applied by Spike in 32b mode.
  if (get_core(0)->get_xlen() == 32) {
    commit_log.pc &= 0xffffffffULL;
    commit_log.data &= 0xffffffffULL;
  }

  // TODO FIXME There's no direct access to the exception status anymore.
  //commit_log.was_exception = get_core(0)->get_state()->was_exception;

  return commit_log;
}

void sim_spike_t::clint_tick() {
  // TODO FIXME 'clint' is a private member of sim.
  //clint->increment(1);
}

#if 0 // FORNOW Unused code, disable until needed.
void sim_spike_t::set_debug(bool value)
{
  debug = value;
}

void sim_spike_t::set_log(bool value)
{
  log = value;
}

void sim_spike_t::set_histogram(bool value)
{
  histogram_enabled = value;
  for (size_t i = 0; i < procs.size(); i++) {
    procs[i]->set_histogram(histogram_enabled);
  }
}

void sim_spike_t::set_procs_debug(bool value)
{
  for (size_t i=0; i< procs.size(); i++)
    procs[i]->set_debug(value);
}

bool sim_spike_t::mmio_load(reg_t addr, size_t len, uint8_t* bytes)
{
  if (addr + len < addr)
    return false;
  return bus.load(addr, len, bytes);
}

bool sim_spike_t::mmio_store(reg_t addr, size_t len, const uint8_t* bytes)
{
  if (addr + len < addr)
    return false;
  return bus.store(addr, len, bytes);
}

void sim_spike_t::make_bootrom()
{
  start_pc = 0x80000000;

  #include "bootrom.h"

  std::vector<char> rom((char*)reset_vec, (char*)reset_vec + sizeof(reset_vec));

  boot_rom.reset(new rom_device_t(rom));
  bus.add_device(DEFAULT_RSTVEC, boot_rom.get());
}

char* sim_spike_t::addr_to_mem(reg_t addr) {
  auto desc = bus.find_device(addr);
  if (auto mem = dynamic_cast<mem_t*>(desc.second))
    if (addr - desc.first < mem->size())
      return mem->contents() + (addr - desc.first);
  return NULL;
}
#endif
