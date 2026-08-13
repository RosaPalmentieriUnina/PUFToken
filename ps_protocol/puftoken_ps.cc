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

puftoken_ret_t puftoken_ps_token_batch_cb(
    PaymentSystem *const ps,
    const uint8_t *const rcvd_pkt,
    const uint32_t pkt_len)
{
    if ((ps == NULL) || (rcvd_pkt == NULL))
    {
        return RET_INVALID_ARGUMENT;
    }

    if (ps->ps_state != PS_WAIT_TOKEN_BATCH)
    {
        return RET_INVALID_STATE;
    }

    if (pkt_len < TOKEN_BATCH_BASE_SIZE)
    {
        return RET_INVALID_PACKET;
    }

    if (rcvd_pkt[0] != (uint8_t)TOKEN_BATCH)
    {
        return RET_INVALID_PACKET;
    }

    size_t offset = MESSAGE_TYPE_SIZE;

    const puftoken_id_t received_dev_id =
        U8_TO_ID_BE(
            &rcvd_pkt[offset]);

    offset += ID_SIZE;

    if (received_dev_id != ps->dev_id)
    {
        return RET_INVALID_PACKET;
    }

    const token_count_t received_token_count =
        U8_TO_TOKEN_COUNT_BE(
            &rcvd_pkt[offset]);

    offset += TOKEN_COUNT_SIZE;

    const size_t expected_packet_size =
        TOKEN_BATCH_SIZE(received_token_count);

    if (pkt_len != expected_packet_size)
    {
        return RET_INVALID_PACKET;
    }

    puftoken_status_t response_status =
        STATUS_ACCEPT;

    if (received_token_count != ps->ats)
    {
        response_status =
            STATUS_INVALID_TOKEN;
    }

    const size_t a_offset =
        TOKEN_BATCH_BASE_SIZE;

    const size_t b_offset =
        a_offset +
        ((size_t)received_token_count * BLOCK_SIZE);

    puf_link_t last_received_link =
        ps->q;

    if (response_status == STATUS_ACCEPT)
    {
        for (token_count_t j = 0U;
             j < received_token_count;
             ++j)
        {
            puftoken_block_t encrypted_link = {};

            memcpy(
                encrypted_link.bytes,
                &rcvd_pkt[a_offset +
                          ((size_t)j * BLOCK_SIZE)],
                BLOCK_SIZE);

            puftoken_block_t decrypted_link = {};

            puftoken_ret_t result =
                puftoken_symmetric_decrypt(
                    &ps->ra,
                    &encrypted_link,
                    &decrypted_link);

            if (result != RET_OK)
            {
                return result;
            }

            const puf_link_t received_link =
                U8_TO_PUF_LINK_BE(
                    decrypted_link.bytes);

            puftoken_bank_signature_t bank_token = {};

            memcpy(
                bank_token.bytes,
                &rcvd_pkt[b_offset +
                          ((size_t)j * BANK_SIGNATURE_SIZE)],
                BANK_SIGNATURE_SIZE);

            result =
                puftoken_bank_verify(
                    &ps->bank_public_key,
                    decrypted_link.bytes,
                    sizeof(puf_link_t),
                    &bank_token);

            if (result == RET_SIGNATURE_INVALID)
            {
                response_status =
                    STATUS_INVALID_TOKEN;

                break;
            }

            if (result != RET_OK)
            {
                return result;
            }

            last_received_link =
                received_link;
        }
    }

    /*
     * If every token is valid, certify:
     *
     * Q_new || NRL
     */
    puftoken_bank_signature_t new_certified_state = {};

    if (response_status == STATUS_ACCEPT)
    {
        uint8_t new_state_plaintext[STATE_PLAINTEXT_SIZE] = {0U};

        PUF_LINK_TO_U8_BE(
            last_received_link,
            new_state_plaintext);

        TOKEN_COUNT_TO_U8_BE(
            ps->nrl,
            &new_state_plaintext[sizeof(puf_link_t)]);

        const puftoken_ret_t result =
            puftoken_bank_sign(
                &ps->bank_private_key,
                new_state_plaintext,
                STATE_PLAINTEXT_SIZE,
                &new_certified_state);

        if (result != RET_OK)
        {
            return result;
        }
    }

    /*
     * Construct SPEND_RESULT.
     */
    size_t response_offset = 0U;

    ps->unicast_tsmt_buff[response_offset] =
        (uint8_t)SPEND_RESULT;

    response_offset += MESSAGE_TYPE_SIZE;

    ID_TO_U8_BE(
        ps->id,
        &ps->unicast_tsmt_buff[response_offset]);

    response_offset += ID_SIZE;

    ps->unicast_tsmt_buff[response_offset] =
        (uint8_t)response_status;

    response_offset += STATUS_SIZE;

    if (response_status == STATUS_ACCEPT)
    {
        memcpy(
            &ps->unicast_tsmt_buff[response_offset],
            new_certified_state.bytes,
            BANK_SIGNATURE_SIZE);

        response_offset +=
            BANK_SIGNATURE_SIZE;
    }

    ps->unicast_tsmt_len =
        (uint32_t)response_offset;

    ps->unicast_is_present = 1U;

    /*
     * The transaction is complete on the Payment System side.
     */
    ps->dev_id = 0U;
    ps->ats = 0U;
    ps->q = 0U;
    ps->rl = 0U;
    ps->nrl = 0U;

    ps->ps_state =
        PS_WAIT_SPEND_REQUEST;

    return RET_OK;
}