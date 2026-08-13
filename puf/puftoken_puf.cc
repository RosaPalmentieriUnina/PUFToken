#include "puftoken_puf.h"

#if defined(__GNUC__) || defined(__clang__) /*GNUC direttiva Windows per GCC, metre clang stessa direttiva ma per Linux */
#define PUFTOKEN_WEAK __attribute__((weak))
#else
#define PUFTOKEN_WEAK
#endif

#define SIMULATED_PUF_MASK 0xA5A5A5A5U

PUFTOKEN_WEAK puftoken_ret_t next_puf_link(
    const puf_link_t current_link,
    puf_link_t* const next_link)
{
    if (next_link == NULL) {
        return RET_INVALID_ARGUMENT;
    }

    *next_link = (puf_link_t)(current_link ^ (current_link << 1U) ^ SIMULATED_PUF_MASK );

    return RET_OK;
}