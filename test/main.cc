#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include "puftoken_common.h"
#include "puftoken_dev.h"
#include "puftoken_ps.h"
#include "puftoken_crypto.h"
#include "puftoken_puf.h"
#include "puftoken_setup.h"

int main()
{

    printf("\n---------------------- DEVICE TEST ----------------------\n");

    Device dev = {};

    puftoken_key_t ra = {};

    puftoken_bank_signature_t certified_state = {};

    const token_count_t test_token_count = 10U;

    puftoken_bank_signature_t bank_tokens[10] = {};

    /*
     * Assign recognizable test values.
     */
    ra.bytes[0] = 0xAAU;

    certified_state.bytes[0] = 0xCCU;
    bank_tokens[0].bytes[0] = 0xDDU;

    const puftoken_ret_t setup_result =
        puftoken_dev_setup(
            &dev,
            1U,
            2U,
            &ra,
            0x11223344U,
            test_token_count,
            test_token_count,
            &certified_state,
            bank_tokens);

    if (setup_result != RET_OK)
    {
        printf("Device setup failed.\n");
        return 1;
    }

    printf("Device setup completed correctly.\n");

    printf(
        "Device ID: %" PRIu16 "\n",
        dev.id);

    printf(
        "Payment System ID: %" PRIu16 "\n",
        dev.ps_id);

    printf(
        "Device Q: 0x%08" PRIX32 "\n",
        dev.q);

    printf(
        "Device RL: %" PRIu16 "\n",
        dev.rl);

    printf(
        "Issued tokens: %" PRIu16 "\n",
        dev.iss_tok_count);

    printf(
        "RA first byte: 0x%02" PRIX8 "\n",
        dev.ra.bytes[0]);

    printf(
        "Certified state first byte: 0x%02" PRIX8 "\n",
        dev.certified_state.bytes[0]);

    printf(
        "First Bank token first byte: 0x%02" PRIX8 "\n",
        dev.bank_tokens[0].bytes[0]);

    printf("\n---------------------- PAYMENT SYSTEM TEST ----------------------\n");

    PaymentSystem ps = {};

    puftoken_bank_public_key_t bank_public_key = {};
    puftoken_bank_private_key_t bank_private_key = {};

    const puftoken_ret_t key_pair_result =
        puftoken_bank_generate_key_pair(
            &bank_public_key,
            &bank_private_key);

    if (key_pair_result != RET_OK)
    {
        printf("Bank key-pair generation failed.\n");
        return 1;
    }

    if ((bank_private_key.bytes[0] != 0xA0U) ||
        (bank_public_key.bytes[0] != 0xFAU))
    {
        printf("Bank key-pair generation test failed.\n");
        return 1;
    }

    printf("Bank key pair generated correctly.\n");

    printf(
        "Bank private key first byte: 0x%02" PRIX8 "\n",
        bank_private_key.bytes[0]);

    printf(
        "Bank public key first byte:  0x%02" PRIX8 "\n",
        bank_public_key.bytes[0]);

    const puftoken_ret_t ps_setup_result =
        puftoken_ps_setup(
            &ps,
            2U,
            &ra,
            &bank_public_key,
            &bank_private_key);

    if (memcmp(&ps.bank_public_key, &bank_public_key, sizeof(ps.bank_public_key)) != 0)
    {
        printf("Bank public key was not copied correctly.\n");
        return 1;
    }

    if (memcmp(&ps.bank_private_key, &bank_private_key, sizeof(ps.bank_private_key)) != 0)
    {
        printf("Bank private key was not copied correctly.\n");
        return 1;
    }

    printf("Bank private key first byte: 0x%02" PRIX8 "\n", ps.bank_private_key.bytes[0]);

    if (ps_setup_result != RET_OK)
    {
        printf("Payment System setup failed.\n");
        return 1;
    }

    /*
     * Verify the most important initialized fields.
     */
    if ((ps.id != 2U) ||
        (ps.ps_state != PS_WAIT_SPEND_REQUEST) ||
        (ps.ra.bytes[0] != 0xAAU) ||
        (ps.bank_public_key.bytes[0] != 0xFAU) ||
        (ps.unicast_tsmt_len != 0U) ||
        (ps.unicast_is_present != 0U))
    {
        printf("Payment System setup test failed.\n");
        return 1;
    }

    printf("Payment System setup completed correctly.\n");

    printf(
        "Payment System ID: %" PRIu16 "\n",
        ps.id);

    printf(
        "Payment System state: %u\n",
        (unsigned int)ps.ps_state);

    printf(
        "RA first byte: 0x%02" PRIX8 "\n",
        ps.ra.bytes[0]);

    printf(
        "Bank public key first byte: 0x%02" PRIX8 "\n",
        ps.bank_public_key.bytes[0]);

    printf("\n---------------------- CRYPTO TEST ----------------------\n");

    /*
     * Build the serialized representation of: Q || RL
     */
    uint8_t state_plaintext[STATE_PLAINTEXT_SIZE] = {0U};

    const puf_link_t test_q = 0x11223344U;
    const token_count_t test_rl = 10U;

    PUF_LINK_TO_U8_BE(
        test_q,
        state_plaintext);

    TOKEN_COUNT_TO_U8_BE(
        test_rl,
        &state_plaintext[sizeof(puf_link_t)]);

    /*
     * Sign the state using the Bank private key.
     */
    puftoken_bank_signature_t state_signature = {};

    const puftoken_ret_t sign_result =
        puftoken_bank_sign(
            &bank_private_key,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &state_signature);

    if (sign_result != RET_OK)
    {
        printf("Bank signature generation failed.\n");
        return 1;
    }

    printf("Bank signature generated correctly.\n");

    printf(
        "Signature first byte: 0x%02" PRIX8 "\n",
        state_signature.bytes[0]);

    puftoken_bank_signature_t second_signature = {};

    if (puftoken_bank_sign(
            &bank_private_key,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &second_signature) != RET_OK)
    {
        printf("Second Bank signature generation failed.\n");
        return 1;
    }

    if (memcmp(
            &state_signature,
            &second_signature,
            sizeof(state_signature)) != 0)
    {
        printf("Simulated signature is not deterministic.\n");
        return 1;
    }

    printf("Deterministic signature test passed.\n");

    const puftoken_ret_t verify_result =
        puftoken_bank_verify(
            &bank_public_key,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &state_signature);

    if (verify_result != RET_OK)
    {
        printf("Valid Bank signature was rejected.\n");
        return 1;
    }

    printf("Valid Bank signature accepted correctly.\n");

    uint8_t modified_state[STATE_PLAINTEXT_SIZE] = {0U};

    memcpy(
        modified_state,
        state_plaintext,
        STATE_PLAINTEXT_SIZE);

    /*
     * Alter one byte of Q.
     */
    modified_state[0] ^= 0x01U;

    const puftoken_ret_t modified_data_result =
        puftoken_bank_verify(
            &bank_public_key,
            modified_state,
            STATE_PLAINTEXT_SIZE,
            &state_signature);

    if (modified_data_result != RET_SIGNATURE_INVALID)
    {
        printf("Modified data signature test failed.\n");
        return 1;
    }

    printf("Modified data rejected correctly.\n");

    puftoken_bank_signature_t modified_signature =
        state_signature;

    /*
     * Alter one byte of the signature.
     */
    modified_signature.bytes[0] ^= 0x01U;

    const puftoken_ret_t modified_signature_result =
        puftoken_bank_verify(
            &bank_public_key,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &modified_signature);

    if (modified_signature_result != RET_SIGNATURE_INVALID)
    {
        printf("Modified signature test failed.\n");
        return 1;
    }

    printf("Modified signature rejected correctly.\n");

    if (puftoken_bank_verify(
            NULL,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &state_signature) != RET_INVALID_ARGUMENT)
    {
        printf("NULL public-key verification test failed.\n");
        return 1;
    }

    printf(
        "\n---------------------- SYMMETRIC CRYPTO TEST ----------------------\n");

    puftoken_key_t symmetric_test_key = {};

    for (uint32_t i = 0U; i < KEY_SIZE; ++i)
    {
        symmetric_test_key.bytes[i] = (uint8_t)(0x10U + i);
    }

    puftoken_block_t plaintext = {};
    puftoken_block_t ciphertext = {};
    puftoken_block_t recovered_plaintext = {};

    for (uint32_t i = 0U; i < BLOCK_SIZE; ++i)
    {
        plaintext.bytes[i] = (uint8_t)i;
    }

    puftoken_ret_t symmetric_result =
        puftoken_symmetric_encrypt(
            &symmetric_test_key,
            &plaintext,
            &ciphertext);

    if (symmetric_result != RET_OK)
    {
        printf("Symmetric encryption failed.\n");
        return 1;
    }

    if (memcmp(&plaintext, &ciphertext, sizeof(plaintext)) == 0)
    {
        printf("Symmetric encryption did not modify the plaintext.\n");
        return 1;
    }

    printf("Symmetric encryption completed correctly.\n");

    symmetric_result =
        puftoken_symmetric_decrypt(
            &symmetric_test_key,
            &ciphertext,
            &recovered_plaintext);

    if (symmetric_result != RET_OK)
    {
        printf("Symmetric decryption failed.\n");
        return 1;
    }

    if (memcmp(&plaintext, &recovered_plaintext, sizeof(plaintext)) != 0)
    {
        printf("Recovered plaintext does not match the original plaintext.\n");
        return 1;
    }

    printf("Symmetric decryption completed correctly.\n");
    printf("Recovered plaintext matches the original plaintext.\n");

    if (puftoken_symmetric_encrypt(NULL, &plaintext, &ciphertext) != RET_INVALID_ARGUMENT)
    {
        printf("Symmetric invalid-argument test failed.\n");
        return 1;
    }

    printf("Symmetric invalid-argument test completed correctly.\n");

    printf("\n---------------------- PUF CHAIN TEST ----------------------\n");

    const puf_link_t initial_link = 0x11223344U;

    puf_link_t first_link = 0U;
    puf_link_t second_link = 0U;
    puf_link_t third_link = 0U;

    if (next_puf_link(
            initial_link,
            &first_link) != RET_OK)
    {
        printf("First simulated PUF evaluation failed.\n");
        return 1;
    }

    if (next_puf_link(
            first_link,
            &second_link) != RET_OK)
    {
        printf("Second simulated PUF evaluation failed.\n");
        return 1;
    }

    if (next_puf_link(
            second_link,
            &third_link) != RET_OK)
    {
        printf("Third simulated PUF evaluation failed.\n");
        return 1;
    }

    printf("Simulated PUF chain generated correctly.\n");

    printf(
        "Initial link: 0x%08" PRIX32 "\n",
        initial_link);

    printf(
        "First link:   0x%08" PRIX32 "\n",
        first_link);

    printf(
        "Second link:  0x%08" PRIX32 "\n",
        second_link);

    printf(
        "Third link:   0x%08" PRIX32 "\n",
        third_link);

    /*
     * Verify the expected chain values.
     */
    if ((first_link != 0x96C3F069U) ||
        (second_link != 0x1EE1B51EU) ||
        (third_link != 0x86877A87U))
    {
        printf("Unexpected simulated PUF chain values.\n");
        return 1;
    }

    printf("Simulated PUF expected-values test passed.\n");

    /*
     * Verify that a NULL output pointer is rejected.
     */
    if (next_puf_link(
            initial_link,
            NULL) != RET_INVALID_ARGUMENT)
    {
        printf("NULL next-link test failed.\n");
        return 1;
    }

    printf("NULL next-link test passed.\n");

    printf("\n---------------------- SETUP TEST ----------------------\n");

    Device setup_dev = {};
    PaymentSystem setup_ps = {};

    const puf_link_t setup_initial_q =
        0x11223344U;

    const token_count_t setup_token_count =
        10U;

    const puftoken_ret_t complete_setup_result =
        puftoken_setup(
            &setup_dev,
            &setup_ps,
            1U,
            2U,
            setup_initial_q,
            setup_token_count);

    if (complete_setup_result != RET_OK)
    {
        printf("Complete PUFToken setup failed.\n");
        return 1;
    }

    if ((setup_dev.id != 1U) ||
        (setup_dev.ps_id != 2U) ||
        (setup_dev.q != setup_initial_q) ||
        (setup_dev.rl != setup_token_count) ||
        (setup_dev.iss_tok_count != setup_token_count) ||
        (setup_dev.dev_state != DEV_READY))
    {
        printf("Complete Device setup test failed.\n");
        return 1;
    }

    if ((setup_ps.id != 2U) ||
        (setup_ps.ps_state != PS_WAIT_SPEND_REQUEST))
    {
        printf("Complete Payment System setup test failed.\n");
        return 1;
    }

    if (setup_ps.bank_private_key.bytes[0] != 0xA0U)
    {
        printf("Bank private key was not installed in the Payment System.\n");
        return 1;
    }

    printf("Payment System Bank private key first byte: 0x%02" PRIX8 "\n", setup_ps.bank_private_key.bytes[0]);

    if (memcmp(
            &setup_dev.ra,
            &setup_ps.ra,
            sizeof(setup_dev.ra)) != 0)
    {
        printf("RA mismatch after complete setup.\n");
        return 1;
    }

    uint8_t setup_state[STATE_PLAINTEXT_SIZE] = {0U};

    PUF_LINK_TO_U8_BE(
        setup_dev.q,
        setup_state);

    TOKEN_COUNT_TO_U8_BE(
        setup_dev.rl,
        &setup_state[sizeof(puf_link_t)]);

    if (puftoken_bank_verify(
            &setup_ps.bank_public_key,
            setup_state,
            STATE_PLAINTEXT_SIZE,
            &setup_dev.certified_state) != RET_OK)
    {
        printf("Initial certified-state verification failed.\n");
        return 1;
    }

    printf("Initial certified state verified correctly.\n");

    puf_link_t first_setup_link = 0U;

    if (next_puf_link(
            setup_dev.q,
            &first_setup_link) != RET_OK)
    {
        printf("First setup PUF-link generation failed.\n");
        return 1;
    }

    uint8_t first_setup_link_data[sizeof(puf_link_t)] = {0U};

    PUF_LINK_TO_U8_BE(
        first_setup_link,
        first_setup_link_data);

    if (puftoken_bank_verify(
            &setup_ps.bank_public_key,
            first_setup_link_data,
            sizeof(first_setup_link_data),
            &setup_dev.bank_tokens[0]) != RET_OK)
    {
        printf("First setup token verification failed.\n");
        return 1;
    }

    printf("First setup token verified correctly.\n");

    printf(
        "\n---------------------- SPEND REQUEST TEST ----------------------\n");

    const token_count_t spend_test_ats = 3U;

    const puftoken_ret_t spend_request_result =
        puftoken_dev_start_spending(
            &setup_dev,
            spend_test_ats);

    if (spend_request_result != RET_OK)
    {
        printf("SPEND_REQUEST generation failed.\n");
        return 1;
    }

    if ((setup_dev.dev_state != DEV_WAIT_SPEND_AUTH) ||
        (setup_dev.ats != spend_test_ats) ||
        (setup_dev.unicast_is_present != 1U) ||
        (setup_dev.unicast_tsmt_len != SPEND_REQUEST_SIZE))
    {

        printf("Device state after SPEND_REQUEST is invalid.\n");
        return 1;
    }

    if ((setup_dev.q != setup_initial_q) || (setup_dev.rl != setup_token_count))
    {
        printf("Q or RL changed while constructing SPEND_REQUEST.\n");
        return 1;
    }

    size_t request_offset = 0U;

    if (setup_dev.unicast_tsmt_buff[request_offset] != (uint8_t)SPEND_REQUEST)
    {
        printf("Invalid SPEND_REQUEST message type.\n");
        return 1;
    }

    request_offset += MESSAGE_TYPE_SIZE;

    const puftoken_id_t request_dev_id = U8_TO_ID_BE(&setup_dev.unicast_tsmt_buff[request_offset]);

    if (request_dev_id != setup_dev.id)
    {
        printf("Invalid Device ID in SPEND_REQUEST.\n");
        return 1;
    }

    request_offset += ID_SIZE;

    puftoken_block_t request_encrypted_state = {};
    puftoken_block_t request_plaintext = {};

    memcpy(
        request_encrypted_state.bytes,
        &setup_dev.unicast_tsmt_buff[request_offset],
        BLOCK_SIZE);

    request_offset += BLOCK_SIZE;

    if (puftoken_symmetric_decrypt(
            &setup_dev.ra,
            &request_encrypted_state,
            &request_plaintext) != RET_OK)
    {
        printf("SPEND_REQUEST state decryption failed.\n");
        return 1;
    }

    const puf_link_t request_q =
        U8_TO_PUF_LINK_BE(
            request_plaintext.bytes);

    const token_count_t request_rl =
        U8_TO_TOKEN_COUNT_BE(
            &request_plaintext.bytes[sizeof(puf_link_t)]);

    if ((request_q != setup_initial_q) || (request_rl != setup_token_count))
    {
        printf("Invalid Q or RL inside SPEND_REQUEST.\n");
        return 1;
    }

    puftoken_bank_signature_t request_certified_state = {};

    memcpy(
        request_certified_state.bytes,
        &setup_dev.unicast_tsmt_buff[request_offset],
        BANK_SIGNATURE_SIZE);

    request_offset += BANK_SIGNATURE_SIZE;

    if (memcmp(
            &request_certified_state,
            &setup_dev.certified_state,
            sizeof(request_certified_state)) != 0)
    {
        printf("Certified state mismatch in SPEND_REQUEST.\n");
        return 1;
    }

    if (puftoken_bank_verify(
            &setup_ps.bank_public_key,
            request_plaintext.bytes,
            STATE_PLAINTEXT_SIZE,
            &request_certified_state) != RET_OK)
    {
        printf("SPEND_REQUEST certified state verification failed.\n");
        return 1;
    }

    const token_count_t request_ats =
        U8_TO_TOKEN_COUNT_BE(
            &setup_dev.unicast_tsmt_buff[request_offset]);

    request_offset += TOKEN_COUNT_SIZE;

    if (request_ats != spend_test_ats)
    {
        printf("Invalid ATS in SPEND_REQUEST.\n");
        return 1;
    }

    if (request_offset != SPEND_REQUEST_SIZE)
    {
        printf("Invalid SPEND_REQUEST size.\n");
        return 1;
    }

    printf("SPEND_REQUEST generated and verified correctly.\n");

    printf(
        "\n---------------------- SPEND AUTH TEST ----------------------\n");

    const puf_link_t expected_ps_q = setup_dev.q;
    const token_count_t expected_ps_rl = setup_dev.rl;
    const token_count_t expected_ps_ats = setup_dev.ats;
    const token_count_t expected_ps_nrl = (token_count_t)(expected_ps_rl - expected_ps_ats);

    const puftoken_ret_t spend_auth_result = puftoken_ps_spend_request_cb(&setup_ps, setup_dev.unicast_tsmt_buff, setup_dev.unicast_tsmt_len);

    if (spend_auth_result != RET_OK)
    {
        printf("SPEND_REQUEST processing failed.\n");
        return 1;
    }

    if ((setup_ps.ps_state != PS_WAIT_TOKEN_BATCH) ||
        (setup_ps.dev_id != setup_dev.id) ||
        (setup_ps.q != expected_ps_q) ||
        (setup_ps.rl != expected_ps_rl) ||
        (setup_ps.ats != expected_ps_ats) ||
        (setup_ps.nrl != expected_ps_nrl))
    {
        printf("Payment System transaction context is invalid.\n");
        return 1;
    }

    if ((setup_ps.unicast_is_present != 1U) ||
        (setup_ps.unicast_tsmt_len != SPEND_AUTH_RESULT_OK_SIZE))
    {
        printf("Invalid SPEND_AUTH_RESULT buffer state.\n");
        return 1;
    }

    size_t auth_offset = 0U;

    if (setup_ps.unicast_tsmt_buff[auth_offset] !=
        (uint8_t)SPEND_AUTH_RESULT)
    {
        printf("Invalid SPEND_AUTH_RESULT message type.\n");
        return 1;
    }

    auth_offset += MESSAGE_TYPE_SIZE;

    const puftoken_id_t auth_ps_id =
        U8_TO_ID_BE(
            &setup_ps.unicast_tsmt_buff[auth_offset]);

    auth_offset += ID_SIZE;

    if (auth_ps_id != setup_ps.id)
    {
        printf("Invalid Payment System ID in SPEND_AUTH_RESULT.\n");
        return 1;
    }

    const puftoken_status_t auth_status =
        (puftoken_status_t)
            setup_ps.unicast_tsmt_buff[auth_offset];

    auth_offset += STATUS_SIZE;

    if (auth_status != STATUS_OK)
    {
        printf("SPEND_AUTH_RESULT did not contain STATUS_OK.\n");
        return 1;
    }

    const token_count_t auth_nrl =
        U8_TO_TOKEN_COUNT_BE(
            &setup_ps.unicast_tsmt_buff[auth_offset]);

    auth_offset += TOKEN_COUNT_SIZE;

    if (auth_nrl != expected_ps_nrl)
    {
        printf("Invalid NRL in SPEND_AUTH_RESULT.\n");
        return 1;
    }

    if (auth_offset != SPEND_AUTH_RESULT_OK_SIZE)
    {
        printf("Invalid SPEND_AUTH_RESULT size.\n");
        return 1;
    }

    printf(
        "SPEND_REQUEST accepted correctly. NRL = %" PRIu16 "\n",
        auth_nrl);

    PaymentSystem integrity_test_ps = {};

    if (puftoken_ps_setup(
            &integrity_test_ps,
            setup_ps.id,
            &setup_ps.ra,
            &setup_ps.bank_public_key,
            &setup_ps.bank_private_key) != RET_OK)
    {
        printf("Integrity-test Payment System setup failed.\n");
        return 1;
    }

    uint8_t tampered_request[SPEND_REQUEST_SIZE] = {};

    memcpy(
        tampered_request,
        setup_dev.unicast_tsmt_buff,
        SPEND_REQUEST_SIZE);

    const size_t request_signature_offset =
        MESSAGE_TYPE_SIZE +
        ID_SIZE +
        BLOCK_SIZE;

    tampered_request[request_signature_offset] ^= 0x01U;

    if (puftoken_ps_spend_request_cb(
            &integrity_test_ps,
            tampered_request,
            SPEND_REQUEST_SIZE) != RET_OK)
    {
        printf("Integrity-failure request processing failed.\n");
        return 1;
    }

    if ((integrity_test_ps.ps_state != PS_WAIT_SPEND_REQUEST) ||
        (integrity_test_ps.unicast_is_present != 1U) ||
        (integrity_test_ps.unicast_tsmt_len !=
         SPEND_AUTH_RESULT_BASE_SIZE))
    {
        printf("INTEGRITY_FAIL response state is invalid.\n");
        return 1;
    }

    const size_t auth_status_offset =
        MESSAGE_TYPE_SIZE + ID_SIZE;

    if (integrity_test_ps.unicast_tsmt_buff[auth_status_offset] !=
        (uint8_t)STATUS_INTEGRITY_FAIL)
    {
        printf("Expected STATUS_INTEGRITY_FAIL.\n");
        return 1;
    }

    printf("Modified certified state rejected correctly.\n");

    PaymentSystem amount_test_ps = {};

    if (puftoken_ps_setup(
            &amount_test_ps,
            setup_ps.id,
            &setup_ps.ra,
            &setup_ps.bank_public_key,
            &setup_ps.bank_private_key) != RET_OK)
    {
        printf("Amount-test Payment System setup failed.\n");
        return 1;
    }

    uint8_t invalid_amount_request[SPEND_REQUEST_SIZE] = {};

    memcpy(
        invalid_amount_request,
        setup_dev.unicast_tsmt_buff,
        SPEND_REQUEST_SIZE);

    const size_t request_ats_offset =
        SPEND_REQUEST_SIZE - TOKEN_COUNT_SIZE;

    const token_count_t invalid_ats =
        (token_count_t)(expected_ps_rl + 1U);

    TOKEN_COUNT_TO_U8_BE(
        invalid_ats,
        &invalid_amount_request[request_ats_offset]);

    if (puftoken_ps_spend_request_cb(
            &amount_test_ps,
            invalid_amount_request,
            SPEND_REQUEST_SIZE) != RET_OK)
    {
        printf("Invalid-amount request processing failed.\n");
        return 1;
    }

    if ((amount_test_ps.ps_state != PS_WAIT_SPEND_REQUEST) ||
        (amount_test_ps.unicast_tsmt_len !=
         SPEND_AUTH_RESULT_BASE_SIZE) ||
        (amount_test_ps.unicast_tsmt_buff[auth_status_offset] !=
         (uint8_t)STATUS_INVALID_AMOUNT))
    {
        printf("Expected STATUS_INVALID_AMOUNT.\n");
        return 1;
    }

    printf("Invalid amount rejected correctly.\n");

    printf(
        "\n---------------------- TOKEN BATCH TEST ----------------------\n");

    const puf_link_t q_before_token_batch = setup_dev.q;
    const token_count_t rl_before_token_batch = setup_dev.rl;
    const token_count_t ats_before_token_batch = setup_dev.ats;

    const puftoken_ret_t token_batch_result =
        puftoken_dev_spend_auth_cb(
            &setup_dev,
            setup_ps.unicast_tsmt_buff,
            setup_ps.unicast_tsmt_len);

    if (token_batch_result != RET_OK)
    {
        printf("SPEND_AUTH_RESULT processing failed.\n");
        return 1;
    }

    if ((setup_dev.dev_state != DEV_WAIT_SPEND_RESULT) ||
        (setup_dev.nrl != setup_ps.nrl) ||
        (setup_dev.rl != rl_before_token_batch) ||
        (setup_dev.unicast_is_present != 1U) ||
        (setup_dev.unicast_tsmt_len !=
         TOKEN_BATCH_SIZE(ats_before_token_batch)))
    {
        printf("Device state after TOKEN_BATCH generation is invalid.\n");
        return 1;
    }

    size_t batch_offset = 0U;

    if (setup_dev.unicast_tsmt_buff[batch_offset] !=
        (uint8_t)TOKEN_BATCH)
    {
        printf("Invalid TOKEN_BATCH message type.\n");
        return 1;
    }

    batch_offset += MESSAGE_TYPE_SIZE;

    const puftoken_id_t batch_dev_id =
        U8_TO_ID_BE(
            &setup_dev.unicast_tsmt_buff[batch_offset]);

    batch_offset += ID_SIZE;

    if (batch_dev_id != setup_dev.id)
    {
        printf("Invalid Device ID in TOKEN_BATCH.\n");
        return 1;
    }

    const token_count_t batch_token_count =
        U8_TO_TOKEN_COUNT_BE(
            &setup_dev.unicast_tsmt_buff[batch_offset]);

    batch_offset += TOKEN_COUNT_SIZE;

    if (batch_token_count != ats_before_token_batch)
    {
        printf("Invalid token count in TOKEN_BATCH.\n");
        return 1;
    }

    const size_t batch_a_offset =
        TOKEN_BATCH_BASE_SIZE;

    const size_t batch_b_offset =
        batch_a_offset +
        ((size_t)batch_token_count * BLOCK_SIZE);

    puf_link_t expected_link = q_before_token_batch;

    for (token_count_t j = 0U;
         j < batch_token_count;
         ++j)
    {
        puf_link_t next_expected_link = 0U;

        if (next_puf_link(
                expected_link,
                &next_expected_link) != RET_OK)
        {
            printf("Expected PUF link generation failed.\n");
            return 1;
        }

        puftoken_block_t encrypted_link = {};
        puftoken_block_t decrypted_link = {};

        memcpy(
            encrypted_link.bytes,
            &setup_dev.unicast_tsmt_buff[batch_a_offset +
                                         ((size_t)j * BLOCK_SIZE)],
            BLOCK_SIZE);

        if (puftoken_symmetric_decrypt(
                &setup_dev.ra,
                &encrypted_link,
                &decrypted_link) != RET_OK)
        {
            printf("TOKEN_BATCH link decryption failed.\n");
            return 1;
        }

        const puf_link_t received_link =
            U8_TO_PUF_LINK_BE(
                decrypted_link.bytes);

        if (received_link != next_expected_link)
        {
            printf("Invalid PUF link in TOKEN_BATCH.\n");
            return 1;
        }

        puftoken_bank_signature_t received_bank_token = {};

        memcpy(
            received_bank_token.bytes,
            &setup_dev.unicast_tsmt_buff[batch_b_offset +
                                         ((size_t)j * BANK_SIGNATURE_SIZE)],
            BANK_SIGNATURE_SIZE);

        if (puftoken_bank_verify(
                &setup_ps.bank_public_key,
                decrypted_link.bytes,
                sizeof(puf_link_t),
                &received_bank_token) != RET_OK)
        {
            printf("Invalid Bank token in TOKEN_BATCH.\n");
            return 1;
        }

        expected_link = next_expected_link;
    }

    if (setup_dev.q != expected_link)
    {
        printf("Q was not advanced correctly.\n");
        return 1;
    }

    if (setup_dev.rl != rl_before_token_batch)
    {
        printf("RL was updated before final ACCEPT.\n");
        return 1;
    }

    printf(
        "TOKEN_BATCH generated and verified correctly.\n");

    printf(
        "\n---------------------- SPEND RESULT TEST ----------------------\n");

    PaymentSystem invalid_token_ps = setup_ps;

    const size_t test_batch_b_offset =
        TOKEN_BATCH_BASE_SIZE +
        ((size_t)setup_dev.ats * BLOCK_SIZE);

    setup_dev.unicast_tsmt_buff[test_batch_b_offset] ^= 0x01U;

    const puftoken_ret_t invalid_token_result =
        puftoken_ps_token_batch_cb(
            &invalid_token_ps,
            setup_dev.unicast_tsmt_buff,
            setup_dev.unicast_tsmt_len);

    setup_dev.unicast_tsmt_buff[test_batch_b_offset] ^= 0x01U;

    if (invalid_token_result != RET_OK)
    {
        printf("Invalid TOKEN_BATCH processing failed.\n");
        return 1;
    }

    const size_t spend_result_status_offset =
        MESSAGE_TYPE_SIZE + ID_SIZE;

    if ((invalid_token_ps.ps_state !=
         PS_WAIT_SPEND_REQUEST) ||
        (invalid_token_ps.unicast_tsmt_len !=
         SPEND_RESULT_BASE_SIZE) ||
        (invalid_token_ps.unicast_tsmt_buff[spend_result_status_offset] !=
         (uint8_t)STATUS_INVALID_TOKEN))
    {
        printf("Expected STATUS_INVALID_TOKEN.\n");
        return 1;
    }

    printf("Invalid Bank token rejected correctly.\n");

    const puf_link_t expected_new_q =
        setup_dev.q;

    const token_count_t expected_new_rl =
        setup_dev.nrl;

    const puftoken_ret_t final_result =
        puftoken_ps_token_batch_cb(
            &setup_ps,
            setup_dev.unicast_tsmt_buff,
            setup_dev.unicast_tsmt_len);

    if (final_result != RET_OK)
    {
        printf("TOKEN_BATCH processing failed.\n");
        return 1;
    }

    if ((setup_ps.ps_state != PS_WAIT_SPEND_REQUEST) ||
        (setup_ps.unicast_is_present != 1U) ||
        (setup_ps.unicast_tsmt_len !=
         SPEND_RESULT_ACCEPT_SIZE))
    {
        printf("Payment System final state is invalid.\n");
        return 1;
    }

    if ((setup_ps.dev_id != 0U) ||
        (setup_ps.ats != 0U) ||
        (setup_ps.q != 0U) ||
        (setup_ps.rl != 0U) ||
        (setup_ps.nrl != 0U))
    {
        printf("Payment System transaction context was not cleared.\n");
        return 1;
    }

    size_t result_offset = 0U;

    if (setup_ps.unicast_tsmt_buff[result_offset] !=
        (uint8_t)SPEND_RESULT)
    {
        printf("Invalid SPEND_RESULT message type.\n");
        return 1;
    }

    result_offset += MESSAGE_TYPE_SIZE;

    const puftoken_id_t result_ps_id =
        U8_TO_ID_BE(
            &setup_ps.unicast_tsmt_buff[result_offset]);

    result_offset += ID_SIZE;

    if (result_ps_id != setup_ps.id)
    {
        printf("Invalid Payment System ID in SPEND_RESULT.\n");
        return 1;
    }

    const puftoken_status_t final_status =
        (puftoken_status_t)
            setup_ps.unicast_tsmt_buff[result_offset];

    result_offset += STATUS_SIZE;

    if (final_status != STATUS_ACCEPT)
    {
        printf("Expected STATUS_ACCEPT.\n");
        return 1;
    }

    puftoken_bank_signature_t received_new_state = {};

    memcpy(
        received_new_state.bytes,
        &setup_ps.unicast_tsmt_buff[result_offset],
        BANK_SIGNATURE_SIZE);

    result_offset += BANK_SIGNATURE_SIZE;

    if (result_offset != SPEND_RESULT_ACCEPT_SIZE)
    {
        printf("Invalid SPEND_RESULT size.\n");
        return 1;
    }

    uint8_t expected_new_state[STATE_PLAINTEXT_SIZE] = {0U};

    PUF_LINK_TO_U8_BE(
        expected_new_q,
        expected_new_state);

    TOKEN_COUNT_TO_U8_BE(
        expected_new_rl,
        &expected_new_state[sizeof(puf_link_t)]);

    if (puftoken_bank_verify(
            &setup_ps.bank_public_key,
            expected_new_state,
            STATE_PLAINTEXT_SIZE,
            &received_new_state) != RET_OK)
    {
        printf("New certified state is invalid.\n");
        return 1;
    }

    printf(
        "TOKEN_BATCH accepted and new state certified correctly.\n");

    printf(
        "\n---------------------- FINAL DEVICE TEST ----------------------\n");

    /*
     * Save the values that the Device must commit after receiving
     * STATUS_ACCEPT.
     *
     * Q has already been advanced while TOKEN_BATCH was generated.
     * NRL is still waiting to be committed as the new RL.
     */
    const puf_link_t final_expected_q =
        setup_dev.q;

    const token_count_t final_expected_rl =
        setup_dev.nrl;

    /*
     * Save the new certified state contained in SPEND_RESULT before
     * giving the packet to the Device.
     */
    puftoken_bank_signature_t expected_final_certified_state = {};

    memcpy(
        expected_final_certified_state.bytes,
        &setup_ps.unicast_tsmt_buff[SPEND_RESULT_BASE_SIZE],
        BANK_SIGNATURE_SIZE);

    /*
     * Deliver SPEND_RESULT to the Device.
     */
    const puftoken_ret_t device_final_result =
        puftoken_dev_spend_result_cb(
            &setup_dev,
            setup_ps.unicast_tsmt_buff,
            setup_ps.unicast_tsmt_len);

    if (device_final_result != RET_OK)
    {
        printf("SPEND_RESULT processing failed.\n");
        return 1;
    }

    /*
     * The Device must return to the READY state.
     */
    if (setup_dev.dev_state != DEV_READY)
    {
        printf("Device did not return to DEV_READY.\n");
        return 1;
    }

    /*
     * Q must not change here because it was already advanced
     * while TOKEN_BATCH was generated.
     */
    if (setup_dev.q != final_expected_q)
    {
        printf("Q changed while processing final ACCEPT.\n");
        return 1;
    }

    /*
     * NRL must now become the new RL.
     */
    if (setup_dev.rl != final_expected_rl)
    {
        printf("RL was not updated to NRL.\n");
        return 1;
    }

    /*
     * The Device must store n_new as its new certified state.
     */
    if (memcmp(
            &setup_dev.certified_state,
            &expected_final_certified_state,
            sizeof(setup_dev.certified_state)) != 0)
    {
        printf("New certified state was not stored correctly.\n");
        return 1;
    }

    /*
     * Verify, as part of the test, that the stored certified state
     * is really a valid Bank signature for:
     *
     * Q_new || RL_new
     *
     * This verification is performed by the test code, not by
     * puftoken_dev_spend_result_cb().
     */
    uint8_t final_state_plaintext[STATE_PLAINTEXT_SIZE] = {0U};

    PUF_LINK_TO_U8_BE(
        setup_dev.q,
        final_state_plaintext);

    TOKEN_COUNT_TO_U8_BE(
        setup_dev.rl,
        &final_state_plaintext[sizeof(puf_link_t)]);

    if (puftoken_bank_verify(
            &setup_ps.bank_public_key,
            final_state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &setup_dev.certified_state) != RET_OK)
    {
        printf("Stored final certified state is invalid.\n");
        return 1;
    }

    /*
     * The temporary transaction context must have been cleared.
     */
    if ((setup_dev.ats != 0U) ||
        (setup_dev.nrl != 0U) ||
        (setup_dev.unicast_tsmt_len != 0U) ||
        (setup_dev.unicast_is_present != 0U))
    {
        printf("Device transaction context was not cleared.\n");
        return 1;
    }

    printf(
        "Payment completed and Device state updated correctly.\n");

    printf(
        "Final RL: %" PRIu16 "\n",
        setup_dev.rl);

    /*
     * ------------------------------------------------------------
     * Test the STATUS_INVALID_TOKEN branch.
     *
     * We use a copy of the Device so that the successfully completed
     * transaction above is not modified.
     * ------------------------------------------------------------
     */
    printf(
        "\n---------------------- INVALID FINAL RESULT TEST ----------------------\n");

    Device invalid_result_dev = setup_dev;

    /*
     * Simulate the situation immediately before the final response:
     * Q has already advanced and the Device is waiting for
     * SPEND_RESULT.
     */
    invalid_result_dev.dev_state =
        DEV_WAIT_SPEND_RESULT;

    invalid_result_dev.ats = 1U;
    invalid_result_dev.nrl =
        (token_count_t)(invalid_result_dev.rl - 1U);

    /*
     * Build:
     *
     * TYPE | PS_ID | STATUS_INVALID_TOKEN
     */
    uint8_t invalid_spend_result[SPEND_RESULT_BASE_SIZE] = {0U};

    size_t invalid_result_offset = 0U;

    invalid_spend_result[invalid_result_offset] =
        (uint8_t)SPEND_RESULT;

    invalid_result_offset += MESSAGE_TYPE_SIZE;

    ID_TO_U8_BE(
        invalid_result_dev.ps_id,
        &invalid_spend_result[invalid_result_offset]);

    invalid_result_offset += ID_SIZE;

    invalid_spend_result[invalid_result_offset] =
        (uint8_t)STATUS_INVALID_TOKEN;

    invalid_result_offset += STATUS_SIZE;

    if (invalid_result_offset !=
        SPEND_RESULT_BASE_SIZE)
    {
        printf("Invalid test SPEND_RESULT size.\n");
        return 1;
    }

    const puf_link_t q_before_invalid_result =
        invalid_result_dev.q;

    const token_count_t rl_before_invalid_result =
        invalid_result_dev.rl;

    /*
     * Process STATUS_INVALID_TOKEN.
     */
    const puftoken_ret_t invalid_final_result =
        puftoken_dev_spend_result_cb(
            &invalid_result_dev,
            invalid_spend_result,
            SPEND_RESULT_BASE_SIZE);

    if (invalid_final_result != RET_OK)
    {
        printf("STATUS_INVALID_TOKEN processing failed.\n");
        return 1;
    }

    /*
     * The Device must require a new issuance.
     */
    if (invalid_result_dev.dev_state !=
        DEV_NEEDS_REISSUE)
    {
        printf(
            "Device did not enter DEV_NEEDS_REISSUE.\n");
        return 1;
    }

    /*
     * No rollback of Q is allowed.
     */
    if (invalid_result_dev.q !=
        q_before_invalid_result)
    {
        printf(
            "Q was rolled back after STATUS_INVALID_TOKEN.\n");
        return 1;
    }

    /*
     * RL must not be committed because the payment failed.
     */
    if (invalid_result_dev.rl !=
        rl_before_invalid_result)
    {
        printf(
            "RL changed after STATUS_INVALID_TOKEN.\n");
        return 1;
    }

    /*
     * The temporary transaction values must be cleared.
     */
    if ((invalid_result_dev.ats != 0U) ||
        (invalid_result_dev.nrl != 0U) ||
        (invalid_result_dev.unicast_tsmt_len != 0U) ||
        (invalid_result_dev.unicast_is_present != 0U))
    {
        printf(
            "Invalid-result transaction context was not cleared.\n");
        return 1;
    }

    printf(
        "STATUS_INVALID_TOKEN handled correctly: "
        "Device requires token reissue.\n");

    printf(
        "\n---------------------- SECOND PAYMENT TEST ----------------------\n");

    /*
     * State after the first successful payment:
     *
     * iss_tok_count = 10
     * RL            = 7
     *
     * The first Bank token that must be used by the second
     * payment is therefore:
     *
     * iss_tok_count - RL = 3
     *
     * i.e. bank_tokens[3].
     */
    const token_count_t second_payment_ats = 2U;

    const puf_link_t second_initial_q =
        setup_dev.q;

    const token_count_t second_initial_rl =
        setup_dev.rl;

    const token_count_t second_first_token_index =
        (token_count_t)(setup_dev.iss_tok_count -
                        setup_dev.rl);

    if (second_first_token_index != 3U)
    {
        printf(
            "Unexpected first token index for second payment.\n");
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 1. DEVICE -> SPEND_REQUEST
     * ------------------------------------------------------------
     */
    if (puftoken_dev_start_spending(
            &setup_dev,
            second_payment_ats) != RET_OK)
    {
        printf(
            "Second SPEND_REQUEST generation failed.\n");
        return 1;
    }

    if ((setup_dev.dev_state != DEV_WAIT_SPEND_AUTH) ||
        (setup_dev.ats != second_payment_ats))
    {
        printf(
            "Invalid Device state after second SPEND_REQUEST.\n");
        return 1;
    }

    /*
     * Q and RL must not change while SPEND_REQUEST is built.
     */
    if ((setup_dev.q != second_initial_q) ||
        (setup_dev.rl != second_initial_rl))
    {
        printf(
            "Q or RL changed during second SPEND_REQUEST.\n");
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 2. PAYMENT SYSTEM -> process SPEND_REQUEST
     * ------------------------------------------------------------
     */
    if (puftoken_ps_spend_request_cb(
            &setup_ps,
            setup_dev.unicast_tsmt_buff,
            setup_dev.unicast_tsmt_len) != RET_OK)
    {
        printf(
            "Second SPEND_REQUEST processing failed.\n");
        return 1;
    }

    const token_count_t second_expected_nrl =
        (token_count_t)(second_initial_rl -
                        second_payment_ats);

    if ((setup_ps.ps_state != PS_WAIT_TOKEN_BATCH) ||
        (setup_ps.ats != second_payment_ats) ||
        (setup_ps.rl != second_initial_rl) ||
        (setup_ps.nrl != second_expected_nrl))
    {
        printf(
            "Invalid Payment System state during second payment.\n");
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 3. DEVICE -> process SPEND_AUTH_RESULT and build TOKEN_BATCH
     * ------------------------------------------------------------
     */
    if (puftoken_dev_spend_auth_cb(
            &setup_dev,
            setup_ps.unicast_tsmt_buff,
            setup_ps.unicast_tsmt_len) != RET_OK)
    {
        printf(
            "Second SPEND_AUTH_RESULT processing failed.\n");
        return 1;
    }

    if ((setup_dev.dev_state != DEV_WAIT_SPEND_RESULT) ||
        (setup_dev.nrl != second_expected_nrl) ||
        (setup_dev.rl != second_initial_rl))
    {
        printf(
            "Invalid Device state after second TOKEN_BATCH.\n");
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * Verify the TOKEN_BATCH generated during the second payment.
     * ------------------------------------------------------------
     */
    const token_count_t second_batch_token_count =
        U8_TO_TOKEN_COUNT_BE(
            &setup_dev.unicast_tsmt_buff[MESSAGE_TYPE_SIZE + ID_SIZE]);

    if (second_batch_token_count !=
        second_payment_ats)
    {
        printf(
            "Invalid TOKEN_COUNT in second TOKEN_BATCH.\n");
        return 1;
    }

    const size_t second_a_offset =
        TOKEN_BATCH_BASE_SIZE;

    const size_t second_b_offset =
        second_a_offset +
        ((size_t)second_batch_token_count *
         BLOCK_SIZE);

    puf_link_t second_expected_link =
        second_initial_q;

    for (token_count_t j = 0U;
         j < second_batch_token_count;
         ++j)
    {
        /*
         * Calculate the PUF link that should have been generated.
         */
        puf_link_t next_expected_link = 0U;

        if (next_puf_link(
                second_expected_link,
                &next_expected_link) != RET_OK)
        {
            printf(
                "Second-payment expected PUF link generation failed.\n");
            return 1;
        }

        /*
         * Recover A[j].
         */
        puftoken_block_t second_encrypted_link = {};
        puftoken_block_t second_decrypted_link = {};

        memcpy(
            second_encrypted_link.bytes,
            &setup_dev.unicast_tsmt_buff[second_a_offset +
                                         ((size_t)j * BLOCK_SIZE)],
            BLOCK_SIZE);

        if (puftoken_symmetric_decrypt(
                &setup_dev.ra,
                &second_encrypted_link,
                &second_decrypted_link) != RET_OK)
        {
            printf(
                "Second TOKEN_BATCH link decryption failed.\n");
            return 1;
        }

        const puf_link_t second_received_link =
            U8_TO_PUF_LINK_BE(
                second_decrypted_link.bytes);

        if (second_received_link !=
            next_expected_link)
        {
            printf(
                "Invalid PUF link in second TOKEN_BATCH.\n");
            return 1;
        }

        /*
         * Recover B[j].
         */
        puftoken_bank_signature_t
            second_received_bank_token = {};

        memcpy(
            second_received_bank_token.bytes,
            &setup_dev.unicast_tsmt_buff[second_b_offset +
                                         ((size_t)j *
                                          BANK_SIGNATURE_SIZE)],
            BANK_SIGNATURE_SIZE);

        /*
         * Verify that B[j] is a valid Bank signature
         * for the recovered link.
         */
        if (puftoken_bank_verify(
                &setup_ps.bank_public_key,
                second_decrypted_link.bytes,
                sizeof(puf_link_t),
                &second_received_bank_token) != RET_OK)
        {
            printf(
                "Invalid Bank token in second TOKEN_BATCH.\n");
            return 1;
        }

        /*
         * Most importantly, verify that the Device used the
         * correct Bank token index.
         *
         * First payment consumed:
         * bank_tokens[0], [1], [2]
         *
         * Second payment must therefore use:
         * bank_tokens[3], [4]
         */
        const token_count_t expected_bank_token_index =
            (token_count_t)(second_first_token_index + j);

        if (memcmp(
                &second_received_bank_token,
                &setup_dev.bank_tokens[expected_bank_token_index],
                sizeof(second_received_bank_token)) != 0)
        {
            printf(
                "Wrong Bank token index in second payment.\n");
            return 1;
        }

        second_expected_link =
            next_expected_link;
    }

    /*
     * Q must now point to the last generated PUF link.
     */
    if (setup_dev.q != second_expected_link)
    {
        printf(
            "Q was not advanced correctly in second payment.\n");
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 4. PAYMENT SYSTEM -> verify TOKEN_BATCH and build SPEND_RESULT
     * ------------------------------------------------------------
     */
    if (puftoken_ps_token_batch_cb(
            &setup_ps,
            setup_dev.unicast_tsmt_buff,
            setup_dev.unicast_tsmt_len) != RET_OK)
    {
        printf(
            "Second TOKEN_BATCH processing failed.\n");
        return 1;
    }

    const size_t second_result_status_offset =
        MESSAGE_TYPE_SIZE + ID_SIZE;

    if ((setup_ps.ps_state != PS_WAIT_SPEND_REQUEST) ||
        (setup_ps.unicast_tsmt_len !=
         SPEND_RESULT_ACCEPT_SIZE) ||
        (setup_ps.unicast_tsmt_buff[second_result_status_offset] !=
         (uint8_t)STATUS_ACCEPT))
    {
        printf(
            "Second payment was not accepted.\n");
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * 5. DEVICE -> process final SPEND_RESULT
     * ------------------------------------------------------------
     */
    if (puftoken_dev_spend_result_cb(
            &setup_dev,
            setup_ps.unicast_tsmt_buff,
            setup_ps.unicast_tsmt_len) != RET_OK)
    {
        printf(
            "Second SPEND_RESULT processing failed.\n");
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * Verify the final Device state.
     * ------------------------------------------------------------
     */
    if (setup_dev.dev_state != DEV_READY)
    {
        printf(
            "Device did not return to DEV_READY "
            "after second payment.\n");
        return 1;
    }

    if (setup_dev.rl != second_expected_nrl)
    {
        printf(
            "Invalid final RL after second payment.\n");
        return 1;
    }

    if (setup_dev.q != second_expected_link)
    {
        printf(
            "Invalid final Q after second payment.\n");
        return 1;
    }

    /*
     * Verify the new certified state:
     *
     * Sign_PRB(Q_new || RL_new)
     */
    uint8_t second_final_state[STATE_PLAINTEXT_SIZE] = {0U};

    PUF_LINK_TO_U8_BE(
        setup_dev.q,
        second_final_state);

    TOKEN_COUNT_TO_U8_BE(
        setup_dev.rl,
        &second_final_state[sizeof(puf_link_t)]);

    if (puftoken_bank_verify(
            &setup_ps.bank_public_key,
            second_final_state,
            STATE_PLAINTEXT_SIZE,
            &setup_dev.certified_state) != RET_OK)
    {
        printf(
            "Second payment final certified state is invalid.\n");
        return 1;
    }

    /*
     * Temporary transaction state must again be clear.
     */
    if ((setup_dev.ats != 0U) ||
        (setup_dev.nrl != 0U) ||
        (setup_dev.unicast_tsmt_len != 0U) ||
        (setup_dev.unicast_is_present != 0U))
    {
        printf(
            "Second-payment transaction context was not cleared.\n");
        return 1;
    }

    printf(
        "Second payment completed correctly.\n");

    printf(
        "Second payment used Bank tokens starting from index %" PRIu16 ".\n",
        second_first_token_index);

    printf(
        "Final RL after two payments: %" PRIu16 "\n",
        setup_dev.rl);

    puftoken_dev_cleanup(&dev);
    puftoken_dev_cleanup(&setup_dev);

    return 0;
}