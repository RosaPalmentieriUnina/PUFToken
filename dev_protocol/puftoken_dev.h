#ifndef PUFTOKEN_DEV_H
#define PUFTOKEN_DEV_H

#define DEV_PC_DBG 1

#if DEV_PC_DBG
#include <stdio.h>
#endif

#include "dev_common.h"

typedef enum
{
    DEV_READY,              /* The Device is not executing a transaction and can start a new spending operation */
    DEV_WAIT_SPEND_AUTH,    /* The Device has sent SPEND_REQUEST and is waiting for SPEND_AUTH_RESULT from the Payment System */
    DEV_WAIT_SPEND_RESULT,  /* The Device has sent TOKEN_BATCH and is waiting for the final SPEND_RESULT from the Payment System */
    DEV_NEEDS_REISSUE
} PUFToken_Dev_State;


typedef struct
{
    puftoken_id_t id;                           /* Identifier of this Device */
    puftoken_id_t ps_id;                        /* Identifier of the Payment System with which the Device is currently communicating */
    PUFToken_Dev_State dev_state;               /* Current state of the Device automaton */

    puftoken_key_t ra;                          /* Session key used to protect messages sent from the Device to the Payment System */

    puf_link_t q;                               /* Q Register */
    token_count_t rl;                           /* Register RL, Remaining Links */

    token_count_t iss_tok_count;                /* Total number of tokens issued to the Device during the initialization phase */
    puftoken_bank_signature_t certified_state;  /* Certified state produced by the Bank: Q || RL */
    puftoken_bank_signature_t* bank_tokens;     /* Tokens approved by the Bank during the initialization phase */
    token_count_t ats;                          /* ATS, Amount To Spend */
    token_count_t nrl;                          /* NRL, New Remaining Links */

    uint8_t* unicast_tsmt_buff;                 /* Buffer containing the next packet that the Device must send to the Payment System */
    size_t unicast_tsmt_capacity;               /* Total number of bytes currently allocated for unicast_tsmt_buff */
    uint32_t unicast_tsmt_len;                  /* Actual number of valid bytes currently stored inside unicast_tsmt_buff */
    uint8_t unicast_is_present;                 /* Flag indicating whether a packet is ready to be transmitted */

} Device;


/*
 * Device protocol functions
 */

/**
 * Initializes the Device structure with the values produced
 * by the simulated initialization phase.
 */
puftoken_ret_t puftoken_dev_setup(
    Device* const dev,
    const puftoken_id_t dev_id,
    const puftoken_id_t ps_id,
    const puftoken_key_t* const ra,
    const puf_link_t initial_q,
    const token_count_t initial_rl,
    const token_count_t issued_token_count,
    const puftoken_bank_signature_t* const certified_state,
    const puftoken_bank_signature_t* const bank_tokens);

/**
 * Releases the dynamic memory owned by the Device.
 */
void puftoken_dev_cleanup(Device* const dev);

/**
 * Starts a new spending transaction.
 *
 * The function checks ATS, constructs SPEND_REQUEST and moves
 * the Device from DEV_READY to DEV_WAIT_SPEND_AUTH.
 */
puftoken_ret_t puftoken_dev_start_spending(
    Device* const dev,
    const token_count_t ats);


/**
 * Processes SPEND_AUTH_RESULT received from the Payment System.
 *
 * If the result is STATUS_OK, the function reads NRL,
 * generates the links to spend and constructs TOKEN_BATCH.
 */
puftoken_ret_t puftoken_dev_spend_auth_cb(
    Device* const dev,
    const uint8_t* const rcvd_pkt,
    const uint32_t pkt_len);


/**
 * Processes the final SPEND_RESULT.
 *
 * In case of ACCEPT, the Device stores the new certified state
 * received from the Payment System.
 */
puftoken_ret_t puftoken_dev_spend_result_cb(
    Device* const dev,
    const uint8_t* const rcvd_pkt,
    const uint32_t pkt_len);


/**
 * Device automaton.
 *
 * It examines the current Device state and the received
 * message type, then invokes the appropriate callback.
 */
puftoken_ret_t puftoken_dev_automa(
    Device* const dev,
    const uint8_t* const rcvd_pkt,
    const uint32_t pkt_len);

    
#endif