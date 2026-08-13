#include "puftoken_ps.h"
#include "../crypto/puftoken_crypto.h"

#include <string.h>

puftoken_ret_t puftoken_ps_setup(
    PaymentSystem *const ps,
    const puftoken_id_t ps_id,
    const puftoken_key_t *const ra,
    const puftoken_bank_public_key_t *const bank_public_key,
    const puftoken_bank_private_key_t *const bank_private_key)
{
    if ((ps == NULL) || (ra == NULL) || (bank_public_key == NULL) || bank_private_key == NULL)
    {
        return RET_INVALID_ARGUMENT;
    }

    memset(ps, 0, sizeof(*ps));

    ps->id = ps_id;

    memcpy(&ps->ra, ra, sizeof(ps->ra));
    memcpy(&ps->bank_public_key, bank_public_key, sizeof(ps->bank_public_key));
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

puftoken_ret_t puftoken_ps_spend_request_cb(
    PaymentSystem *const ps,
    const uint8_t *const rcvd_pkt,
    const uint32_t pkt_len)
{
    if ((ps == NULL) || (rcvd_pkt == NULL))
    {
        return RET_INVALID_ARGUMENT;
    }

    if (ps->ps_state != PS_WAIT_SPEND_REQUEST)
    {
        return RET_INVALID_STATE;
    }

    if (pkt_len != SPEND_REQUEST_SIZE)
    {
        return RET_INVALID_PACKET;
    }

    if (rcvd_pkt[0] != (uint8_t)SPEND_REQUEST)
    {
        return RET_INVALID_PACKET;
    }

    size_t offset = MESSAGE_TYPE_SIZE;

    const puftoken_id_t received_dev_id = U8_TO_ID_BE(&rcvd_pkt[offset]);
    offset += ID_SIZE;

    puftoken_block_t encrypted_state = {};
    memcpy(encrypted_state.bytes, &rcvd_pkt[offset], BLOCK_SIZE);
    offset += BLOCK_SIZE;

    puftoken_bank_signature_t certified_state = {};
    memcpy(certified_state.bytes, &rcvd_pkt[offset], BANK_SIGNATURE_SIZE);
    offset += BANK_SIGNATURE_SIZE;

    const token_count_t received_ats = U8_TO_TOKEN_COUNT_BE(&rcvd_pkt[offset]);
    offset += TOKEN_COUNT_SIZE;

    if (offset != pkt_len)
    {
        return RET_INVALID_PACKET;
    }

    puftoken_block_t state_plaintext = {};
    puftoken_ret_t result = puftoken_symmetric_decrypt(&ps->ra, &encrypted_state, &state_plaintext);

    if (result != RET_OK)
    {
        return result;
    }

    const puf_link_t received_q = U8_TO_PUF_LINK_BE(state_plaintext.bytes);
    const token_count_t received_rl = U8_TO_TOKEN_COUNT_BE(&state_plaintext.bytes[sizeof(puf_link_t)]);

    result = puftoken_bank_verify(&ps->bank_public_key, state_plaintext.bytes, STATE_PLAINTEXT_SIZE, &certified_state);

    puftoken_status_t response_status = STATUS_OK;
    token_count_t calculated_nrl = 0U;

    if (result == RET_SIGNATURE_INVALID)
    {
        response_status = STATUS_INTEGRITY_FAIL;
    }
    else if (result != RET_OK)
    {
        return result;
    }

    if (response_status == STATUS_OK)
    {
        if (received_ats > received_rl)
        {
            response_status = STATUS_INVALID_AMOUNT;
        }
        else
        {
            calculated_nrl =
                (token_count_t)(received_rl - received_ats);
        }
    }

    size_t response_offset = 0U;

    /* TYPE */
    ps->unicast_tsmt_buff[response_offset] = (uint8_t)SPEND_AUTH_RESULT;
    response_offset += MESSAGE_TYPE_SIZE;

    /* TYPE | PS_ID */
    ID_TO_U8_BE(ps->id, &ps->unicast_tsmt_buff[response_offset]);
    response_offset += ID_SIZE;

    /* TYPE | PS_ID | STATUS */
    ps->unicast_tsmt_buff[response_offset] = (uint8_t)response_status;
    response_offset += STATUS_SIZE;

    if (response_status == STATUS_OK)
    {
        /* TYPE | PS_ID | STATUS | NRL */
        TOKEN_COUNT_TO_U8_BE(calculated_nrl, &ps->unicast_tsmt_buff[response_offset]);
        response_offset += TOKEN_COUNT_SIZE;

        ps->dev_id = received_dev_id;
        ps->ats = received_ats;
        ps->q = received_q;
        ps->rl = received_rl;
        ps->nrl = calculated_nrl;

        ps->ps_state = PS_WAIT_TOKEN_BATCH;
    }
    else
    {
        ps->dev_id = 0U;
        ps->ats = 0U;
        ps->q = 0U;
        ps->rl = 0U;
        ps->nrl = 0U;

        ps->ps_state = PS_WAIT_SPEND_REQUEST;
    }

    ps->unicast_tsmt_len = (uint32_t)response_offset;
    ps->unicast_is_present = 1U;

    return RET_OK;
}