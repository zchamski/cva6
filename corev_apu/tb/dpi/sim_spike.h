// See LICENSE for license details.

#ifndef _SIM_SPIKE_H
#define _SIM_SPIKE_H

#include "cfg.h"
#include "debug_module.h"
#include "devices.h"
#include "log_file.h"
#include "processor.h"
#include "sim.h"

#include <fesvr/htif.h>
#include <vector>
#include <map>
#include <string>
#include <memory>
#include <thread>
#include <sys/types.h>

class mmu_t;
class remote_bitbang_t;
class socketif_t;

typedef struct
{
  char     priv;
  uint64_t pc;
  char     is_fp;
  char     rd;
  uint64_t data;
  uint32_t instr;
  // char     was_exception;
} commit_log_t;

// this class encapsulates the processors and memory in a RISC-V machine.
class sim_spike_t : sim_t
{
public:
  sim_spike_t(const cfg_t *cfg,
        std::vector<std::pair<reg_t, mem_t*>> mems,
        const std::vector<std::string>& args,
        size_t max_steps);
  ~sim_spike_t();

  int init_sim();
  void clint_tick();
  commit_log_t tick(size_t n); // step through simulation

private:
};


#endif
