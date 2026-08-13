#include "puftoken_dev.h"

#include "../crypto/puftoken_crypto.h"
#include "../puf/puftoken_puf.h"

#include <string.h>
#include <stdlib.h>

puftoken_ret_t puftoken_dev_setup(
    Device *const dev,
    const puftoken_id_t dev_id,
    const puftoken_id_t ps_id,
    const puftoken_key_t *const ra,
    const puf_link_t initial_q,
    const token_count_t initial_rl,
    const token_count_t issued_token_count,
    const puftoken_bank_signature_t *const certified_state,
    const puftoken_bank_signature_t *const bank_tokens)
{
    if ((dev == NULL) || (ra == NULL) || (certified_state == NULL) || (bank_tokens == NULL))
    {
        return RET_INVALID_ARGUMENT;
    }

    if (issued_token_count == 0U)
    {
        return RET_INVALID_ARGUMENT;
    }

    if (initial_rl > issued_token_count)
    {
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
    dev->bank_tokens = (puftoken_bank_signature_t *)malloc(bank_tokens_size);

    if (dev->bank_tokens == NULL)
    {
        return RET_MEMORY_ERROR;
    }

    dev->unicast_tsmt_buff = (uint8_t *)malloc(tx_buffer_size);

    if (dev->unicast_tsmt_buff == NULL)
    {
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

puftoken_ret_t puftoken_dev_start_spending(Device *const dev, const token_count_t ats)
{

    if (dev == NULL)
    {
        return RET_INVALID_ARGUMENT;
    }

    if (dev->dev_state != DEV_READY)
    {
        return RET_INVALID_STATE;
    }

    if (ats == 0U)
    {
        return RET_INVALID_ARGUMENT;
    }

    if (dev->unicast_tsmt_buff == NULL)
    {
        return RET_INVALID_STATE;
    }

    if (dev->unicast_tsmt_capacity < SPEND_REQUEST_SIZE)
    {
        return RET_BUFFER_TOO_SMALL;
    }

    puftoken_block_t state_plaintext = {};

    PUF_LINK_TO_U8_BE(dev->q, state_plaintext.bytes);
    TOKEN_COUNT_TO_U8_BE(dev->rl, &state_plaintext.bytes[sizeof(puf_link_t)]);

    puftoken_block_t encrypted_state = {};

    const puftoken_ret_t crypto_result = puftoken_symmetric_encrypt(&dev->ra, &state_plaintext, &encrypted_state);

    if (crypto_result != RET_OK)
    {
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

puftoken_ret_t puftoken_dev_spend_auth_cb(
    Device *const dev,
    const uint8_t *const rcvd_pkt,
    const uint32_t pkt_len)
{
    if ((dev == NULL) || (rcvd_pkt == NULL))
    {
        return RET_INVALID_ARGUMENT;
    }

    if (dev->dev_state != DEV_WAIT_SPEND_AUTH)
    {
        return RET_INVALID_STATE;
    }

    if (pkt_len < SPEND_AUTH_RESULT_BASE_SIZE)
    {
        return RET_INVALID_PACKET;
    }

    if (rcvd_pkt[0] != (uint8_t)SPEND_AUTH_RESULT)
    {
        return RET_INVALID_PACKET;
    }

    size_t offset = MESSAGE_TYPE_SIZE;

    const puftoken_id_t received_ps_id =
        U8_TO_ID_BE(
            &rcvd_pkt[offset]);

    offset += ID_SIZE;

    if (received_ps_id != dev->ps_id)
    {
        return RET_INVALID_PACKET;
    }

    const puftoken_status_t status =
        (puftoken_status_t)rcvd_pkt[offset];

    offset += STATUS_SIZE;

    /*
     * A rejected SPEND_REQUEST terminates the current
     * transaction before any PUF link has been consumed.
     */
    if ((status == STATUS_INTEGRITY_FAIL) ||
        (status == STATUS_INVALID_AMOUNT))
    {
        if (pkt_len != SPEND_AUTH_RESULT_BASE_SIZE)
        {
            return RET_INVALID_PACKET;
        }

        dev->ats = 0U;
        dev->nrl = 0U;

        dev->unicast_tsmt_len = 0U;
        dev->unicast_is_present = 0U;

        dev->dev_state = DEV_READY;

        return RET_OK;
    }

    if (status != STATUS_OK)
    {
        return RET_INVALID_PACKET;
    }

    if (pkt_len != SPEND_AUTH_RESULT_OK_SIZE)
    {
        return RET_INVALID_PACKET;
    }

    const token_count_t received_nrl =
        U8_TO_TOKEN_COUNT_BE(
            &rcvd_pkt[offset]);

    offset += TOKEN_COUNT_SIZE;

    if (offset != pkt_len)
    {
        return RET_INVALID_PACKET;
    }

    if (dev->ats > dev->rl)
    {
        return RET_INVALID_STATE;
    }

    const token_count_t expected_nrl =
        (token_count_t)(dev->rl - dev->ats);

    if (received_nrl != expected_nrl)
    {
        return RET_INVALID_PACKET;
    }

    const size_t token_batch_size =
        TOKEN_BATCH_SIZE(dev->ats);

    if ((dev->unicast_tsmt_buff == NULL) ||
        (dev->unicast_tsmt_capacity < token_batch_size))
    {
        return RET_BUFFER_TOO_SMALL;
    }

    if (dev->rl > dev->iss_tok_count)
    {
        return RET_INVALID_STATE;
    }

    const token_count_t first_token_index =
        (token_count_t)(dev->iss_tok_count - dev->rl);

    if (((size_t)first_token_index +
         (size_t)dev->ats) >
        (size_t)dev->iss_tok_count)
    {
        return RET_INVALID_STATE;
    }

    /*
     * Construct TOKEN_BATCH:
     *
     * TYPE | DEVICE_ID | TOKEN_COUNT |
     * A[0] | ... | A[ATS - 1] |
     * B[0] | ... | B[ATS - 1]
     */
    size_t header_offset = 0U;

    dev->unicast_tsmt_buff[header_offset] =
        (uint8_t)TOKEN_BATCH;

    header_offset += MESSAGE_TYPE_SIZE;

    ID_TO_U8_BE(
        dev->id,
        &dev->unicast_tsmt_buff[header_offset]);

    header_offset += ID_SIZE;

    TOKEN_COUNT_TO_U8_BE(
        dev->ats,
        &dev->unicast_tsmt_buff[header_offset]);

    header_offset += TOKEN_COUNT_SIZE;

    const size_t a_offset =
        TOKEN_BATCH_BASE_SIZE;

    const size_t b_offset =
        a_offset +
        ((size_t)dev->ats * BLOCK_SIZE);

    for (token_count_t j = 0U;
         j < dev->ats;
         ++j)
    {
        puf_link_t generated_link = 0U;

        puftoken_ret_t result =
            next_puf_link(
                dev->q,
                &generated_link);

        if (result != RET_OK)
        {
            return result;
        }

        puftoken_block_t link_plaintext = {};

        PUF_LINK_TO_U8_BE(
            generated_link,
            link_plaintext.bytes);

        puftoken_block_t encrypted_link = {};

        result =
            puftoken_symmetric_encrypt(
                &dev->ra,
                &link_plaintext,
                &encrypted_link);

        if (result != RET_OK)
        {
            return result;
        }

        const size_t current_a_offset = a_offset + ((size_t)j * BLOCK_SIZE);

        memcpy(
            &dev->unicast_tsmt_buff[current_a_offset],
            encrypted_link.bytes,
            BLOCK_SIZE);

        const token_count_t bank_token_index = (token_count_t)(first_token_index + j);

        const size_t current_b_offset = b_offset + ((size_t)j * BANK_SIGNATURE_SIZE);

        memcpy(
            &dev->unicast_tsmt_buff[current_b_offset],
            dev->bank_tokens[bank_token_index].bytes,
            BANK_SIGNATURE_SIZE);

        dev->q = generated_link;
    }

    dev->nrl = received_nrl;

    dev->unicast_tsmt_len = (uint32_t)token_batch_size;
    dev->unicast_is_present = 1U;

    dev->dev_state = DEV_WAIT_SPEND_RESULT;

    return RET_OK;
}

void puftoken_dev_cleanup(Device *const dev)
{
    if (dev == NULL)
    {
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