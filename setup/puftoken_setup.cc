#include "puftoken_setup.h"

#include "../crypto/puftoken_crypto.h"
#include "../puf/puftoken_puf.h"

#include <string.h>
#include <stdlib.h>


/*
 * Initial values used only to generate deterministic
 * simulated session keys.
 */
#define SIMULATED_RA_BASE 0x10U


/*
 * Generates deterministic simulated session keys.
 */
static void generate_simulated_session_key(
    puftoken_key_t* const ra)
{
    for (uint32_t i = 0U; i < KEY_SIZE; ++i) {
        ra->bytes[i] = (uint8_t)(SIMULATED_RA_BASE + i);
    }
}


puftoken_ret_t puftoken_setup(
    Device* const dev,
    PaymentSystem* const ps,
    const puftoken_id_t dev_id,
    const puftoken_id_t ps_id,
    const puf_link_t initial_q,
    const token_count_t issued_token_count)
{
    if ((dev == NULL) || (ps == NULL)) {
        return RET_INVALID_ARGUMENT;
    }

    /*
     * At least one token must be issued.
     */
    if (issued_token_count == 0U) {
        return RET_INVALID_ARGUMENT;
    }

    memset(dev, 0, sizeof(*dev));
    memset(ps, 0, sizeof(*ps));

    puftoken_key_t ra = {};

    puftoken_bank_public_key_t bank_public_key = {};
    puftoken_bank_private_key_t bank_private_key = {};

    puftoken_bank_signature_t certified_state = {};

    const size_t bank_tokens_size =
        (size_t)issued_token_count * sizeof(puftoken_bank_signature_t);

    puftoken_bank_signature_t* bank_tokens =
        (puftoken_bank_signature_t*)malloc(bank_tokens_size);

    if (bank_tokens == NULL) {
        return RET_MEMORY_ERROR;
    }

    memset(bank_tokens, 0, bank_tokens_size);

    generate_simulated_session_key(&ra);

    puftoken_ret_t result = puftoken_bank_generate_key_pair(&bank_public_key, &bank_private_key);

    if (result != RET_OK) {
        memset(&bank_private_key, 0, sizeof(bank_private_key));
        free(bank_tokens);

        return result;
    }

    const token_count_t initial_rl = issued_token_count;

    /*
     * State: Q || RL
     */
    uint8_t state_plaintext[STATE_PLAINTEXT_SIZE] = {0U};

    PUF_LINK_TO_U8_BE(initial_q, state_plaintext);

    TOKEN_COUNT_TO_U8_BE(initial_rl, &state_plaintext[sizeof(puf_link_t)]);

    /*
     * The Bank certifies the initial state using its private key.
     */
    result = puftoken_bank_sign(&bank_private_key, state_plaintext, STATE_PLAINTEXT_SIZE, &certified_state);

    if (result != RET_OK) {
        memset(&bank_private_key, 0, sizeof(bank_private_key));
        free(bank_tokens);

        return result;
    }

    puf_link_t current_link = initial_q;

    for (token_count_t i = 0U; i < issued_token_count; ++i) {
        puf_link_t generated_link = 0U;

        result = next_puf_link(current_link, &generated_link);

        if (result != RET_OK) {
            memset(&bank_private_key, 0, sizeof(bank_private_key));
            free(bank_tokens);

            return result;
        }

        uint8_t link_plaintext[sizeof(puf_link_t)] = {0U};

        PUF_LINK_TO_U8_BE(generated_link, link_plaintext);

        /*
         * Store the Bank signature associated with this link.
         */
        result = puftoken_bank_sign(&bank_private_key, link_plaintext, sizeof(link_plaintext), &bank_tokens[i]);

        if (result != RET_OK) {
            memset(&bank_private_key, 0, sizeof(bank_private_key));
            free(bank_tokens);

            return result;
        }

        /*
         * Advance along the simulated PUF chain.
         */
        current_link = generated_link;
    }

    result =
        puftoken_dev_setup(
            dev,
            dev_id,
            ps_id,
            &ra,
            initial_q,
            initial_rl,
            issued_token_count,
            &certified_state,
            bank_tokens);

    if (result != RET_OK) {
        memset(&bank_private_key, 0, sizeof(bank_private_key));
        free(bank_tokens);
        memset(dev, 0, sizeof(*dev));

        return result;
    }

    free(bank_tokens);
    bank_tokens = NULL;

    result =
        puftoken_ps_setup(
            ps,
            ps_id,
            &ra,
            &bank_public_key,
            &bank_private_key);

    if (result != RET_OK)
    {
        memset(&bank_private_key, 0, sizeof(bank_private_key));

        puftoken_dev_cleanup(dev);
        
        memset(dev, 0, sizeof(*dev));
        memset(ps, 0, sizeof(*ps));

        return result;
    }

    memset(&bank_private_key, 0, sizeof(bank_private_key));

    return RET_OK;
}