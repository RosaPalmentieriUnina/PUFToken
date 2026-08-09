#include "puftoken_puf.h"


#define SIMULATED_PUF_MASK 0xA5A5A5A5U

puftoken_ret_t next_puf_link(
    const puf_link_t current_link,
    puf_link_t* const next_link)
{
    if (next_link == NULL) {
        return RET_INVALID_ARGUMENT;
    }

    *next_link = (puf_link_t)(current_link ^ (current_link << 1U) ^ SIMULATED_PUF_MASK );

    return RET_OK;
}