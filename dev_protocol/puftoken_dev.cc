#include "puftoken_dev.h"

#include <string.h>


puftoken_ret_t puftoken_dev_setup(
    Device* const dev,
    const puftoken_id_t dev_id,
    const puftoken_id_t ps_id,
    const puftoken_key_t* const ra,
    const puftoken_key_t* const rb,
    const puf_link_t initial_q,
    const token_count_t initial_rl,
    const token_count_t issued_token_count,
    const puftoken_bank_signature_t* const certified_state,
    const puftoken_bank_signature_t* const bank_tokens)
{
    if ((dev == NULL) || (ra == NULL) || (rb == NULL) || (certified_state == NULL) || (bank_tokens == NULL)) {
        return RET_INVALID_ARGUMENT;
    }

    if ((issued_token_count == 0U) || (issued_token_count > MAX_ISS_TOK)) {
        return RET_INVALID_ARGUMENT;
    }

    if (initial_rl > issued_token_count) {
        return RET_INVALID_ARGUMENT;
    }

    memset(dev, 0, sizeof(*dev));       /* riempie di zero tutta la memoria occupata dalla struttura Device */

    dev->id = dev_id;
    dev->ps_id = ps_id;

    memcpy(&dev->ra, ra, sizeof(dev->ra));
    memcpy(&dev->rb, rb, sizeof(dev->rb));

    dev->q = initial_q;
    dev->rl = initial_rl;
    dev->iss_tok_count = issued_token_count;

    memcpy(&dev->certified_state, certified_state, sizeof(dev->certified_state));
    memcpy(dev->bank_tokens, bank_tokens, (size_t)issued_token_count * sizeof(dev->bank_tokens[0]));

    dev->ats = 0U;
    dev->nrl = 0U;
    dev->q_tmp = initial_q;

    dev->unicast_tsmt_len = 0U;
    dev->unicast_is_present = 0U;

    dev->dev_state = DEV_READY;

    return RET_OK;
}