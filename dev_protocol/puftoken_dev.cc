#include "puftoken_dev.h"
#include "../crypto/puftoken_crypto.h"

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

    memset(dev, 0, sizeof(*dev));

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

puftoken_ret_t puftoken_dev_start_spending(Device* const dev, const token_count_t ats) {
    
    if (dev == NULL) {
        return RET_INVALID_ARGUMENT;
    }

    if (dev->dev_state != DEV_READY) {
        return RET_INVALID_STATE;
    }

    if (ats == 0U) {
        return RET_INVALID_ARGUMENT;
    }

    if (dev->unicast_tsmt_buff == NULL) {
        return RET_INVALID_STATE;
    }

    if (dev->unicast_tsmt_capacity < SPEND_REQUEST_SIZE) {
        return RET_BUFFER_TOO_SMALL;
    }

    puftoken_block_t state_plaintext = {};

    PUF_LINK_TO_U8_BE(dev->q, state_plaintext.bytes);
    TOKEN_COUNT_TO_U8_BE(dev->rl, &state_plaintext.bytes[sizeof(puf_link_t)]);

    puftoken_block_t encrypted_state = {};

    const puftoken_ret_t crypto_result = puftoken_symmetric_encrypt(&dev->ra, &state_plaintext, &encrypted_state);

    if (crypto_result != RET_OK) {
        return crypto_result;
    }

    size_t offset = 0U;

    dev->unicast_tsmt_buff[offset] = (uint8_t)SPEND_REQUEST;
    offset += MESSAGE_TYPE_SIZE;

    ID_TO_U8_BE(dev->id, &dev->unicast_tsmt_buff[offset]);
    offset += ID_SIZE;

    memcpy(&dev->unicast_tsmt_buff[offset], encrypted_state.bytes, BLOCK_SIZE);
    offset += BLOCK_SIZE;

    memcpy(&dev->unicast_tsmt_buff[offset], dev->certified_state.bytes, BANK_SIGNATURE_SIZE);
    offset += BANK_SIGNATURE_SIZE;

    TOKEN_COUNT_TO_U8_BE(ats, &dev->unicast_tsmt_buff[offset]);
    offset += TOKEN_COUNT_SIZE;

    dev->ats = ats;
    dev->nrl = 0U;
    dev->unicast_tsmt_len = (uint32_t)offset;
    dev->unicast_is_present = 1U;
    dev->dev_state = DEV_WAIT_SPEND_AUTH;

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