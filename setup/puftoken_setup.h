#ifndef PUFTOKEN_SETUP_H
#define PUFTOKEN_SETUP_H

#include "../dev_protocol/puftoken_dev.h"
#include "../ps_protocol/puftoken_ps.h"


puftoken_ret_t puftoken_setup(
    Device* const dev,
    PaymentSystem* const ps,
    const puftoken_id_t dev_id,
    const puftoken_id_t ps_id,
    const puf_link_t initial_q,
    const token_count_t issued_token_count);


#endif