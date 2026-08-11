#include "puftoken_ps.h"

#include <string.h>


puftoken_ret_t puftoken_ps_setup(
    PaymentSystem* const ps,
    const puftoken_id_t ps_id,
    const puftoken_key_t* const ra,
    const puftoken_bank_public_key_t* const bank_public_key,
    const puftoken_bank_private_key_t* const bank_private_key)
{
    if ((ps == NULL) || (ra == NULL) || (bank_public_key == NULL) || bank_private_key == NULL) {
        return RET_INVALID_ARGUMENT;
    }

    memset(ps, 0, sizeof(*ps));

    ps->id = ps_id;

    memcpy( &ps->ra, ra, sizeof(ps->ra));
    memcpy( &ps->bank_public_key, bank_public_key, sizeof(ps->bank_public_key));
    memcpy(&ps->bank_private_key, bank_private_key, sizeof(ps->bank_private_key));

    ps->dev_id = 0U;

    ps->ats = 0U;
    ps->q = 0U;
    ps->rl = 0U;
    ps->nrl = 0U;

    ps->unicast_tsmt_len = 0U;
    ps->unicast_is_present = 0U;

    ps->ps_state = PS_WAIT_SPEND_REQUEST;

    return RET_OK;
}