/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#include "kose_tlv.h"
#include "kose_enums.h"
#include "kona_kss_api.h"

#define KOSE_MAX_BUF_SIZE_CMD (255)
#define KOSE_MAX_BUF_SIZE_RSP (255)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / (sizeof(array[0])))
#endif

smStatus_t Kose_API_Select(pKoseSession_t session_ctx, uint8_t *fci, size_t *pfciLen);

smStatus_t Kose_API_GetRandom(pKoseSession_t session_ctx, uint16_t size, uint8_t *randomData, size_t *prandomDataLen);

smStatus_t Kose_API_Initialize_Update(pKoseSession_t session_ctx, uint8_t *resData, size_t *presLen, uint32_t objectID, uint8_t *hostChallenge);

smStatus_t Kose_API_External_Authenticate(pKoseSession_t session_ctx, kss_object_t *keyObj, uint8_t security_level, const uint8_t *hostCrypto, const uint8_t *cmac);

smStatus_t Kose_API_GetData(pKoseSession_t session_ctx, uint8_t objectID, uint8_t *data, size_t *pdataLen);

smStatus_t Kose_API_StoreData(
    pKoseSession_t session_ctx, uint32_t objectID, uint32_t acl, uint8_t p1, uint8_t p2, const uint8_t *objectData, const size_t objectDataLen);

smStatus_t Kose_API_PutKey(
    pKoseSession_t session_ctx, uint32_t objectID, uint32_t acl, uint8_t p1, const uint8_t *objectData, const size_t objectDataLen);

smStatus_t Kose_API_SetLockState(pKoseSession_t session_ctx);

smStatus_t Kose_API_ECDSASign(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen);

smStatus_t Kose_API_EdDSAVerify(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_EDSignatureAlgo_t edSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    KOSE_Result_t *presult);

smStatus_t Kose_API_ECDSAVerify(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    KOSE_Result_t *presult);

