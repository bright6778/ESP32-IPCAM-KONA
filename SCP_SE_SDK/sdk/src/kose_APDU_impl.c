/*
 *
 * Copyright 2025 KONA I
 * SPDX-License-Identifier: Apache-2.0
 */

 #if defined(NONSECURE_WORLD)
 #include "veneer_printf_table.h"
 #endif
 
 #if defined(NONSECURE_WORLD)
 #define NEWLINE() DbgConsole_Printf_NSE("\r\n")
 #else
 #define NEWLINE() printf("\r\n")
 #endif
 
 #include <string.h>
 #include <limits.h>
 #include "kona_kss_kose_types.h"
 #include "kose_APDU_impl.h"
 #include "kss_kose_uart.h"
 #include "kose_tlv.h"
 #include "kss_kose_keyobj.h"

 static const char *TAG = "kose_APDU_impl.c";

 
static void uint32_to_buffer(uint32_t val, size_t bufSzie, uint8_t *buffer) {
    size_t offset = 0;
    switch(bufSzie){
        case 4 : buffer[offset] = (val >> 24) & 0xFF;
        offset++;
        case 3 : buffer[offset] = (val >> 16) & 0xFF;
        offset++;
        case 2 : buffer[offset] = (val >> 8) & 0xFF;
        offset++;
        case 1 : buffer[offset] = val & 0xFF;
    }
}

// SE Select
smStatus_t Kose_API_Select(pKoseSession_t session_ctx, uint8_t *fci, size_t *pfciLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA_00, kKOSE_INS_SELECT, kKOSE_P1_SELECT_NAME, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    uint8_t *pLc = &pCmdbuf[4];
    uint8_t cmdData[] = {0xA0, 0x00, 0x00, 0x01}; 
    lvDataSet_u8buf(&pLc, &cmdbufLen, cmdData, sizeof(cmdData));
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        if(get_u8buf(rspbuf, &rspIndex, rspbufLen - 2, fci, pfciLen) != 0)
        {
            *pfciLen = 0;
        }
    }

    return retStatus;
}
/*
smStatus_t Kose_API_GetRandom(pKoseSession_t session_ctx, uint8_t *random)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA, kKOSE_GET_DATA, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    pCmdbuf[4] = 0x00;
    cmdbufLen = sizeof(hdr.hdr) + 1;
    
    retStatus = DoAPDUTxRx_s_Case2(session_ctx, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (smStatus_t)((pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]));
        }
    }

    return retStatus;
}
*/
smStatus_t Kose_API_GetRandom(pKoseSession_t session_ctx, uint16_t size, uint8_t *randomData, size_t *prandomDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA_00, kKOSE_GET_RANDOM, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    LOGI(TAG, "Kose_API_GetRandom");
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    cmdbuf[4] = size;
    cmdbufLen = sizeof(hdr.hdr) + 1;

    retStatus = DoAPDUTxRx_s_Case2(session_ctx, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        if(get_u8buf(rspbuf, &rspIndex, rspbufLen - 2, randomData, prandomDataLen) != 0)
        {
            *prandomDataLen = 0;
        }
    }

    return retStatus;
}

smStatus_t Kose_API_Initialize_Update(pKoseSession_t session_ctx, uint8_t *resData, size_t *presLen, uint32_t objectID, uint8_t *hostChallenge)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA, kKOSE_INS_INITIALIZE_UPDATE, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    objectID = (objectID & 0xFF00) | (objectID & 0x00FF);
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    uint8_t *pLc = &pCmdbuf[4];
    uint8_t *pCmdOffset = &pCmdbuf[5];  // cmd data pointer
    uint8_t *pData = &pCmdbuf[5];   // total data pointer

    DataSet_u8buf(&pData, (uint8_t*)&objectID, 2);  //Object ID
    DataSet_u8buf(&pData, hostChallenge, 8);       //Host Challenge
    lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, 10);
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        if(get_u8buf(rspbuf, &rspIndex, rspbufLen - 2, resData, presLen) != 0)
        {
            *presLen = 0;
        }
    }

    return retStatus;
}

// External_Authenticate
smStatus_t Kose_API_External_Authenticate(pKoseSession_t session_ctx, kss_object_t *keyObj, uint8_t security_level, const uint8_t *hostCrypto, const uint8_t *cmac)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{(uint8_t)(kKOSE_CLA | 0x04), kKOSE_INS_EXTERNAL_AUTHENTICATE, kKOSE_P1_DEFAULT, security_level}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    
    uint8_t *pLc = &pCmdbuf[4];
    uint8_t *pCmdOffset = &pCmdbuf[5];  // cmd data pointer
    uint8_t *pData = &pCmdbuf[5];   // total data pointer
    
    DataSet_u8buf(&pData, hostCrypto, 8);  //hostCrypto
    DataSet_u8buf(&pData, cmac, 8);        //C-MAC
    lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, 16);
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    
    retStatus = DoAPDUTx_s_Case3(session_ctx, cmdbuf, cmdbufLen);

    return retStatus;
}


// STORE DATA
smStatus_t Kose_API_StoreData(
    pKoseSession_t session_ctx, uint32_t objectID, uint32_t acl, uint8_t p1, uint8_t p2, const uint8_t *objectData, const size_t objectDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA, kKOSE_STORE_DATA, p1, p2}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;
    uint8_t bufObjectID[2] = {0}; 
    uint8_t bufAcl[3] = {0};

    uint32_to_buffer(objectID, 2, bufObjectID);
    uint32_to_buffer(acl, 3, bufAcl);
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    
    uint8_t *pLc = &pCmdbuf[4];
    uint8_t *pCmdOffset = &pCmdbuf[5];  // cmd data pointer
    uint8_t *pData = &pCmdbuf[5];   // total data pointer
    size_t totalSize = 0;

    if(p2 == 0){
        DataSet_u8buf(&pData, bufObjectID, sizeof(bufObjectID));  //Object ID
        DataSet_u8buf(&pData, bufAcl, sizeof(bufAcl));  //ACL
        lvDataSet_u8buf(&pData, &totalSize, objectData, objectDataLen);
        totalSize += (sizeof(bufObjectID) + sizeof(bufAcl));
        lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, totalSize);
        cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    }
    else{
        lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, objectDataLen);
        cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    }
    
    retStatus = DoAPDUTx_s_Case3(session_ctx, cmdbuf, cmdbufLen);

    return retStatus;
}

// PUT KEY
smStatus_t Kose_API_PutKey(
    pKoseSession_t session_ctx, uint32_t objectID, uint32_t acl, uint8_t p1, const uint8_t *objectData, const size_t objectDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{(uint8_t)(kKOSE_CLA | 0x04), kKOSE_PUT_KEY, p1, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;
    uint8_t bufObjectID[2] = {0}; 
    uint8_t bufAcl[3] = {0};

    uint32_to_buffer(objectID, 2, bufObjectID);
    uint32_to_buffer(acl, 3, bufAcl);
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    
    uint8_t *pLc = &pCmdbuf[4];
    uint8_t *pCmdOffset = &pCmdbuf[5];  // cmd data pointer
    uint8_t *pData = &pCmdbuf[5];   // total data pointer
    size_t totalSize = 0;
    
    DataSet_u8buf(&pData, bufObjectID, sizeof(bufObjectID));  //Object ID
    DataSet_u8buf(&pData, bufAcl, sizeof(bufAcl));  //ACL
    totalSize += (sizeof(bufObjectID) + sizeof(bufAcl));
    lvDataSet_u8buf(&pData, &totalSize, objectData, objectDataLen);
    lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, totalSize);
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    
    retStatus = DoAPDUTx_s_Case3(session_ctx, cmdbuf, cmdbufLen);

    return retStatus;
}

// Set Lock State
smStatus_t Kose_API_SetLockState(pKoseSession_t session_ctx)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA, kKOSE_SET_LOCK_STATE, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                       = 5;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    pCmdbuf[5] = 0x00;
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    
    retStatus = DoAPDUTx_s_Case3(session_ctx, cmdbuf, cmdbufLen);

    return retStatus;
}


smStatus_t Kose_API_ECDSASign(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen)
{
    LOGD(TAG, "Kose_API_ECDSASign");
    objectID = (objectID & 0xFF00) | (objectID & 0x00FF);
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{(uint8_t)(kKOSE_CLA | 0x04), kKOSE_INS_SIGN_CDATA, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    uint8_t *pLc = &pCmdbuf[4]; // lc pointer
    uint8_t *pCmdOffset = &pCmdbuf[5];  // cmd data pointer
    uint8_t *pData = &pCmdbuf[5];   // total data pointer
    
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    DataSet_u8buf(&pData, (uint8_t*)&objectID, 2);
    DataSet_u8buf(&pData, inputData, inputDataLen);
    lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, inputDataLen + 2);
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        if(get_u8buf(rspbuf, &rspIndex, rspbufLen - 2, signature, psignatureLen) != 0)
        {
            *psignatureLen = 0;
        }
    }

    return retStatus;
}

smStatus_t Kose_API_ECDSAVerify(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    KOSE_Result_t *presult)
{
    uint8_t hdr_p1 = kKOSE_P1_DEFAULT;
    objectID = (objectID & 0xFFFF);
    if(objectID >= ECC_KEYPAIR_PRIVATE_START && objectID <= ECC_KEYPAIR_PRIVATE_END)
    {
        hdr_p1 = kKOSE_P1_ECC_PRIVATE;
    }
    
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{(uint8_t)(kKOSE_CLA | 0x04), kKOSE_INS_VERIFY_SIGNATURE, hdr_p1, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    LOGD(TAG, "Kose_API_ECDSAVerify");
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    uint8_t *pLc = &pCmdbuf[4];
    lvDataSet_u8buf(&pLc, &cmdbufLen, inputData, inputDataLen);
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    /*
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kKOSE_CLA, kKOSE_INS_CRYPTO, kKOSE_P1_SIGNATURE, kKOSE_P2_VERIFY}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kKOSE_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_ECSignatureAlgo("ecSignAlgo", &pCmdbuf, &cmdbufLen, kKOSE_TAG_2, ecSignAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kKOSE_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("signature", &pCmdbuf, &cmdbufLen, kKOSE_TAG_5, signature, signatureLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        tlvRet    = tlvGet_Result(pRspbuf, &rspIndex, rspbufLen, kKOSE_TAG_1, presult);
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (smStatus_t)((pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]));
        }
    }

cleanup:
*/
    return retStatus;
}

smStatus_t Kose_API_EdDSAVerify(pKoseSession_t session_ctx,
    uint32_t objectID,
    KOSE_EDSignatureAlgo_t edSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    KOSE_Result_t *presult)
{
    uint8_t hdr_p1 = kKOSE_P1_DEFAULT;
    objectID = (objectID & 0xFFFF);
    if(objectID >= ECC_KEYPAIR_PRIVATE_START && objectID <= ECC_KEYPAIR_PRIVATE_END)
    {
        hdr_p1 = kKOSE_P1_ECC_PRIVATE;
    }
    
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{(uint8_t)(kKOSE_CLA | 0x04), kKOSE_INS_VERIFY_SIGNATURE, hdr_p1, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    LOGD(TAG, "Kose_API_ECDSASign");
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    uint8_t *pLc = &pCmdbuf[4];
    lvDataSet_u8buf(&pLc, &cmdbufLen, inputData, inputDataLen);
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    /*
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kKOSE_CLA, kKOSE_INS_CRYPTO, kKOSE_P1_SIGNATURE, kKOSE_P2_VERIFY}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;
    
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kKOSE_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_EDSignatureAlgo("edSignAlgo", &pCmdbuf, &cmdbufLen, kKOSE_TAG_2, edSignAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kKOSE_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("signature", &pCmdbuf, &cmdbufLen, kKOSE_TAG_5, signature, signatureLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        tlvRet    = tlvGet_Result(pRspbuf, &rspIndex, rspbufLen, kKOSE_TAG_1, presult);
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (smStatus_t)((pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]));
        }
    }
    */

    /*
    if (retStatus == SM_OK) {
        if(get_u8buf(rspbuf, &rspIndex, rspbufLen - 2, signature, psignatureLen) != 0)
        {
            *psignatureLen = 0;
        }
    }
cleanup:
    */

    return retStatus;
}

smStatus_t Kose_API_GetData(pKoseSession_t session_ctx, uint8_t objectID, uint8_t *data, size_t *pdataLen)
{
    objectID = (objectID & 0xFFFF);
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA, kKOSE_GET_DATA, (uint8_t)((objectID >> 8) & 0xFF), (uint8_t)(objectID & 0xFF)}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    pCmdbuf[4] = 0x00;
    cmdbufLen = sizeof(hdr.hdr) + 1;
    
    retStatus = DoAPDUTxRx_s_Case2(session_ctx, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        if(get_u8buf(rspbuf, &rspIndex, rspbufLen - 2, data, pdataLen) != 0)
        {
            *pdataLen = 0;
        }
    }

    return retStatus;
}

#if 0
smStatus_t Kose_API_CloseSession(pKoseSession_t session_ctx)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kKOSE_CLA, kKOSE_INS_MGMT, kKOSE_P1_DEFAULT, kKOSE_P2_SESSION_CLOSE}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t iCnt     = 0;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CloseSession []");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        return retStatus;
    }

    if (((session_ctx->value[0] || session_ctx->value[1] || session_ctx->value[2] || session_ctx->value[3] ||
            session_ctx->value[4] || session_ctx->value[5] || session_ctx->value[6] || session_ctx->value[7])) &&
        (session_ctx->hasSession == 1)) {
        retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);
        if (retStatus == SM_OK) {
            for (iCnt = 0; iCnt < 8; iCnt++) {
                session_ctx->value[iCnt] = 0;
            }
            session_ctx->hasSession = 0;
        }
    }
    else {
        LOG_D("CloseSession command is sent only if valid Session exists!!!");
    }
    return retStatus;
}

#endif