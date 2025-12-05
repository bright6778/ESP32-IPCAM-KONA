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
#define DATA_BUF_SIZE 2048

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / (sizeof(array[0])))
#endif

smStatus_t Kose_API_Select(pKoseSession_t session_ctx, uint8_t *fci, size_t *pfciLen);

smStatus_t Kose_API_GetRandom(pKoseSession_t session_ctx, uint16_t size, uint8_t *randomData, size_t *prandomDataLen);

smStatus_t Kose_API_Initialize_Update(pKoseSession_t session_ctx, uint8_t *resData, size_t *presLen, uint32_t objectID, uint8_t *hostChallenge);

smStatus_t Kose_API_External_Authenticate(pKoseSession_t session_ctx, kss_object_t *keyObj, uint8_t security_level, const uint8_t *hostCrypto, const uint8_t *cmac);

smStatus_t Kose_API_GetData(pKoseSession_t session_ctx, uint32_t objectID, uint8_t *data, size_t *pdataLen);

/*
smStatus_t Kose_API_GenerateKey(pKoseSession_t session_ctx, uint8_t p1, uint8_t p2, uint32_t *objectID, uint32_t acl, const uint8_t *hash,
    uint8_t *sig, size_t *pSigLen, uint8_t *publicKey, size_t *pPublicKeyLen);
*/
smStatus_t Kose_API_GenerateKey(pKoseSession_t session_ctx, uint8_t p1, uint8_t p2, uint32_t *objectID, uint32_t acl, uint8_t *publicKey, size_t *pPublicKeyLen);

smStatus_t Kose_API_GenerateKey_OnlyGenKey(pKoseSession_t session_ctx, uint8_t p1, uint8_t p2, uint32_t *objectID, uint32_t acl);

smStatus_t Kose_API_StoreData(
    pKoseSession_t session_ctx, uint32_t objectID, uint32_t acl, uint32_t totalObjectLen, uint8_t p1, uint8_t p2, const uint8_t *objectData, const size_t objectDataLen);

smStatus_t Kose_API_StoreData_MoreBlock(
    pKoseSession_t session_ctx, uint32_t objectID, uint32_t acl, uint8_t p1, uint8_t p2, const uint8_t *objectData, const size_t objectDataLen);

smStatus_t Kose_API_PutKey(
    pKoseSession_t session_ctx, uint32_t objectID, uint32_t acl, const uint8_t *objectData, const size_t objectDataLen);

smStatus_t Kose_API_SetLockState(pKoseSession_t session_ctx);

smStatus_t Kose_API_ECDSASign(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen);

smStatus_t Kose_API_ECDSAVerify(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    KOSE_Result_t *presult);

smStatus_t Kose_API_RSASign(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_RSASignatureAlgo_t rsaSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen);

smStatus_t Kose_API_RSAVerify(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_RSASignatureAlgo_t rsaSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    KOSE_Result_t *presult);

smStatus_t Kose_API_EncryptData(pKoseSession_t session_ctx,
    uint32_t objectID,
    kss_algorithm_t encryptionAlgo,
    const uint8_t *iv,
    size_t ivLen,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *encryptedData,
    size_t *pencryptedDataLen);

smStatus_t Kose_API_DecryptData(pKoseSession_t session_ctx,
    uint32_t objectID,
    kss_algorithm_t encryptionAlgo,
    const uint8_t *iv,
    size_t ivLen,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *encryptedData,
    size_t *pencryptedDataLen);

smStatus_t Kose_API_DeleteSecureObject(pKoseSession_t session_ctx, uint32_t objectID, uint8_t deleteType);

smStatus_t Kose_API_GetKey(pKoseSession_t session_ctx, uint32_t objectID, uint8_t *data, size_t *pdataLen);