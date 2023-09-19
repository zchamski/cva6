// See LICENSE for license details.

#ifndef _SIM_SPIKE_H
#define _SIM_SPIKE_H

#include "Types.h"
#include "cfg.h"
#include "debug_module.h"
#include "devices.h"
#include "log_file.h"
#include "processor.h"
#include "sim.h"

#include <fesvr/htif.h>
#include <fesvr/context.h>
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

namespace openhw
{
// this class encapsulates the processors in a RISC-V machine.
class Simulation : public sim_t
{
protected:
public:
    bool standalone_mode;

    Simulation(const cfg_t *cfg, bool halted,
            std::vector<std::pair<reg_t, mem_t*>> mems,
            std::vector<std::pair<reg_t, abstract_device_t*>> plugin_devices,
            const std::vector<std::string>& args,
            const debug_module_config_t &dm_config, const char *log_path,
            bool dtb_enabled, const char *dtb_file,
            bool socket_enabled,
            FILE *cmd_file, // needed for command line option --cmd
            openhw::Params& params);
    Simulation(const cfg_t *cfg, string elf_path, Params& params);
    ~Simulation();

    void make_mems(const std::vector<mem_cfg_t> &layout);

    /*
     * Run function that runs the whole program while in standalone mode
     * */
    int run();

    /*
     * Step function
     * *
     * * @param n:  Number of instructions to be finished
     * *
     * */
    st_rvfi nstep(size_t n);

    /*
     * Proposed consturctor for the Simulation class
     * *
     * * @param params: parameters to configure the simulation behaviour
     * *
     * */
    Simulation(Params& params);

    /*
     * Function to load a binary into the system
     * */
    int loadElf(string path_elf);

    /*
     * Function to add a Core to the simulation
     * *
     * * @param core: Object of the core
     * */
    void addCore(Processor& core);

    /* Function to del a Core to the simulation
     * *
     * * @param name: name of the core to delete
     * */
    void delCore(Processor& core);

    /* Function to add a Memory to the simulation
     * *
     * * @param memory: Object of the memory
     * */
    //void addMemory(Memory& memory);

    /* Function to del a Memory to the simulation
     * *
     * * @param memory: name of the memory to delete
     * */
    //void delMemory(Memory& memory);

    /* Function to set a bus in the simulation
     * *
     * * @param memory: Object of the bus
     * */
    //void addMemory(bus& bus);

private:
    uint64_t total_steps;
    uint64_t max_steps;
    bool max_steps_enabled;

};
}


#endif
