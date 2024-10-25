#include "nv_opof.h"

struct fw_offload_config off_config_g;

// port IDs initialized inside nv_opof_config_init()
uint16_t portid_pf[MAX_NUM_PF] = { PORT_ID_INVALID, PORT_ID_INVALID };
uint16_t portid_pf_vf[MAX_NUM_PF][MAX_VF_PER_PF] = {
    { PORT_ID_INVALID, PORT_ID_INVALID },
    { PORT_ID_INVALID, PORT_ID_INVALID },
};

uint16_t INITIATOR_PORT_ID;
uint16_t RESPONDER_PORT_ID;

uint32_t MARK_MASK_PORT_IDS = 0xC0000000;
uint32_t MARK_MASK_NEXT_HOP = 0x3FFFFFFF;

uint32_t MARK_PORT_0 = 0x40000000;
uint32_t MARK_PORT_1 = 0x80000000;
