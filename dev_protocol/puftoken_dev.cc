#include "puftoken_dev.h"

#include <string.h>
#include <stdlib.h>


puftoken_ret_t puftoken_dev_setup(
    Device* const dev,
    const puftoken_id_t dev_id,
    const puftoken_id_t ps_id,
    const puftoken_key_t* const ra,
    const puf_link_t initial_q,
    const token_count_t initial_rl,
    const token_count_t issued_token_count,
    const puftoken_bank_signature_t* const certified_state,
    const puftoken_bank_signature_t* const bank_tokens)
{
    if ((dev == NULL) || (ra == NULL) || (certified_state == NULL) || (bank_tokens == NULL)) {
        return RET_INVALID_ARGUMENT;
    }

    if (issued_token_count == 0U) {
        return RET_INVALID_ARGUMENT;
    }

    if (initial_rl > issued_token_count) {
        return RET_INVALID_ARGUMENT;
    }

    memset(dev, 0, sizeof(*dev));       /* riempie di zero tutta la memoria occupata dalla struttura Device */

    dev->id = dev_id;
    dev->ps_id = ps_id;

    memcpy(&dev->ra, ra, sizeof(dev->ra));

    dev->q = initial_q;
    dev->rl = initial_rl;
    dev->iss_tok_count = issued_token_count;

    const size_t bank_tokens_size = (size_t)issued_token_count * sizeof(puftoken_bank_signature_t);
    const size_t tx_buffer_size = TOKEN_BATCH_SIZE(issued_token_count);
    dev->bank_tokens = (puftoken_bank_signature_t*)malloc(bank_tokens_size);

    if (dev->bank_tokens == NULL) {
        return RET_MEMORY_ERROR;
    }

    dev->unicast_tsmt_buff = (uint8_t*)malloc(tx_buffer_size);

    if (dev->unicast_tsmt_buff == NULL) {
        free(dev->bank_tokens);
        dev->bank_tokens = NULL;

        return RET_MEMORY_ERROR;
    }

    dev->unicast_tsmt_capacity = tx_buffer_size;

    memcpy(&dev->certified_state, certified_state, sizeof(dev->certified_state));

    memcpy(dev->bank_tokens, bank_tokens, bank_tokens_size);

    dev->ats = 0U;
    dev->nrl = 0U;

    dev->unicast_tsmt_len = 0U;
    dev->unicast_is_present = 0U;

    dev->dev_state = DEV_READY;

    return RET_OK;
}

void puftoken_dev_cleanup(Device* const dev)
{
    if (dev == NULL) {
        return;
    }

    free(dev->bank_tokens);
    free(dev->unicast_tsmt_buff);

    dev->bank_tokens = NULL;
    dev->unicast_tsmt_buff = NULL;

    dev->unicast_tsmt_capacity = 0U;
    dev->unicast_tsmt_len = 0U;
    dev->unicast_is_present = 0U;
}