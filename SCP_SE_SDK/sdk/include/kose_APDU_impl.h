#include "kose_tlv.h"
#include "kose_enums.h"
#include "kona_kss_api.h"

#define KOSE_MAX_BUF_SIZE_CMD (255)
#define KOSE_MAX_BUF_SIZE_RSP (255)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / (sizeof(array[0])))
#endif

smStatus_t Kose_API_Select(pKoseSession_t session_ctx, uint8_t *fci, size_t *pfciLen);

//smStatus_t Kose_API_GetRandom(pKoseSession_t session_ctx, uint8_t *random);
smStatus_t Kose_API_GetRandom(pKoseSession_t session_ctx, uint16_t size, uint8_t *randomData, size_t *prandomDataLen);

smStatus_t Kose_API_ECDSASign(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen);

smStatus_t Kose_API_GetData(pKoseSession_t session_ctx, uint8_t objectID);