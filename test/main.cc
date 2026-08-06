#include <stdio.h>
#include <inttypes.h>

#include "puftoken_common.h"

int main()
{
    const puf_link_t original_link = 0x11223344;

    uint8_t serialized_link[sizeof(puf_link_t)] = {0};

    /*
     * Serialize the PUF link in big-endian format.
     */
    PUF_LINK_TO_U8_BE(
        original_link,
        serialized_link);

    /*
     * Deserialize the PUF link.
     */
    const puf_link_t recovered_link =
        U8_TO_PUF_LINK_BE(serialized_link);

    if (recovered_link != original_link)
    {
        printf("Big-endian serialization test failed.\n");
        return 1;
    }

    printf("PUFToken proof of concept avviata correttamente.\n");
    printf("Big-endian serialization test passed.\n");

    printf(
        "Original link:  0x%08" PRIX32 "\n",
        original_link);

    printf(
        "Recovered link: 0x%08" PRIX32 "\n",
        recovered_link);

    printf(
        "SPEND_REQUEST size: %zu bytes\n",
        (size_t)PUFTOKEN_SPEND_REQUEST_SIZE);

    printf(
        "Maximum TOKEN_BATCH size: %zu bytes\n",
        (size_t)PUFTOKEN_TOKEN_BATCH_MAX_SIZE);

    return 0;
}