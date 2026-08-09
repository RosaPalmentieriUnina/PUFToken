#ifndef PUFTOKEN_PUF_H
#define PUFTOKEN_PUF_H

#include "../puftoken_common.h"


puftoken_ret_t next_puf_link(
    const puf_link_t current_link,
    puf_link_t* const next_link);


#endif