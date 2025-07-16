/*
 *
 * Copyright 2025 KONA I
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

  /** @file */
#ifdef __cplusplus
extern "C" {
#endif

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
#ifdef ESP_PLATFORM
#include "kss_kose_uart.h"
#endif
#include "kose_tlv.h"
#include "kss_kose_keyobj.h"
#include "kona_kss_debug.h"

static const char *TAG = "kose_APDU_impl.c";
 
static void uint32_to_buffer(const uint32_t val, size_t bufSzie, uint8_t *buffer) {
    size_t offset = 0;
    if (bufSzie >= 4) buffer[offset++] = (val >> 24) & 0xFF;
    if (bufSzie >= 3) buffer[offset++] = (val >> 16) & 0xFF;
    if (bufSzie >= 2) buffer[offset++] = (val >> 8) & 0xFF;
    if (bufSzie >= 1) buffer[offset++] = val & 0xFF;
}

// SE Select
smStatus_t Kose_API_Select(pKoseSession_t session_ctx, uint8_t *fci, size_t *pfciLen)
{
    LOGD(TAG, "Kose_API_Select");

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA_00, kKOSE_INS_SELECT, kKOSE_P1_SELECT_NAME, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    uint8_t *pLc = &pCmdbuf[4];
    const uint8_t cmdData[] = KOSE_APPLET_AID;
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

smStatus_t Kose_API_GetRandom(pKoseSession_t session_ctx, uint16_t size, uint8_t *randomData, size_t *prandomDataLen)
{
    LOGD(TAG, "Kose_API_GetRandom");

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA_00, kKOSE_GET_RANDOM, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

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
    LOGD(TAG, "Kose_API_Initialize_Update");

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA, kKOSE_INS_INITIALIZE_UPDATE, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
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
    LOGD(TAG, "Kose_API_External_Authenticate");

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{(uint8_t)(kKOSE_CLA | 0x04), kKOSE_INS_EXTERNAL_AUTHENTICATE, kKOSE_P1_DEFAULT, security_level}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    
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
    LOGD(TAG, "Kose_API_StoreData");

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA, kKOSE_STORE_DATA, p1, p2}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    uint8_t bufObjectID[2] = {0}; 
    uint8_t bufAclKeyLen[2] = {0};
    uint8_t bufAcl[3] = {0};
    uint32_t aclKeyLen =  objectDataLen + sizeof(bufAcl);

    uint32_to_buffer(objectID, 2, bufObjectID);
    uint32_to_buffer(aclKeyLen, 2, bufAclKeyLen);
    uint32_to_buffer(acl, 3, bufAcl);
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    
    uint8_t *pLc = &pCmdbuf[4];
    uint8_t *pCmdOffset = &pCmdbuf[5];  // cmd data pointer
    uint8_t *pData = &pCmdbuf[5];   // total data pointer
    size_t totalSize = 0;

    if(p2 == 0x00){
        DataSet_u8buf(&pData, bufObjectID, sizeof(bufObjectID));  //Object ID
        DataSet_u8buf(&pData, bufAclKeyLen, sizeof(bufAclKeyLen));  //ACL + key length
        DataSet_u8buf(&pData, bufAcl, sizeof(bufAcl));  //ACL
        DataSet_u8buf(&pData, objectData, objectDataLen);  //object data

        totalSize += (sizeof(bufObjectID) + sizeof(bufAclKeyLen) + sizeof(bufAcl) + objectDataLen);
        lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, totalSize);
        cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    }
    else{
        DataSet_u8buf(&pData, objectData, objectDataLen);  //object data
        lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, objectDataLen);
        cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    }
    
    retStatus = DoAPDUTx_s_Case3(session_ctx, cmdbuf, cmdbufLen);

    return retStatus;
}

// PUT KEY
smStatus_t Kose_API_PutKey(
    pKoseSession_t session_ctx, uint32_t objectID, uint32_t acl, const uint8_t *objectData, const size_t objectDataLen)
{
    LOGD(TAG, "Kose_API_PutKey");

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{(uint8_t)(kKOSE_CLA | 0x04), kKOSE_PUT_KEY, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    uint8_t bufObjectID[2] = {0};
    uint8_t bufAclKeyLen[2] = {0};
    uint8_t bufAcl[3] = {0};
    uint32_t aclKeyLen =  objectDataLen + sizeof(bufAcl);
    
    uint32_to_buffer(objectID, 2, bufObjectID);
    uint32_to_buffer(aclKeyLen, 2, bufAclKeyLen);
    uint32_to_buffer(acl, 3, bufAcl);
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));

    uint8_t *pLc = &pCmdbuf[4];
    uint8_t *pCmdOffset = &pCmdbuf[5];  // cmd data pointer
    uint8_t *pData = &pCmdbuf[5];   // total data pointer
    size_t totalSize = 0;
    
    DataSet_u8buf(&pData, bufObjectID, sizeof(bufObjectID));  //Object ID
    DataSet_u8buf(&pData, bufAclKeyLen, sizeof(bufAclKeyLen));  //ACL + key length
    DataSet_u8buf(&pData, bufAcl, sizeof(bufAcl));  //ACL
    DataSet_u8buf(&pData, objectData, objectDataLen);  //object data
    totalSize += (sizeof(bufObjectID) + sizeof(bufAclKeyLen) + sizeof(bufAcl) + objectDataLen);
    lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, totalSize);
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    
    retStatus = DoAPDUTx_s_Case3(session_ctx, cmdbuf, cmdbufLen);

    return retStatus;
}

// Set Lock State
smStatus_t Kose_API_SetLockState(pKoseSession_t session_ctx)
{
    LOGD(TAG, "Kose_API_SetLockState");

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA, kKOSE_SET_LOCK_STATE, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                       = 5;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    
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

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{(uint8_t)(kKOSE_CLA | 0x04), kKOSE_INS_SIGN_CDATA, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    uint8_t *pLc = &pCmdbuf[4]; // lc pointer
    uint8_t *pCmdOffset = &pCmdbuf[5];  // cmd data pointer
    uint8_t *pData = &pCmdbuf[5];   // total data pointer
    uint8_t bufObjectID[2] = {0}; 
    
    uint32_to_buffer(objectID, 2, bufObjectID);
    
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    DataSet_u8buf(&pData, bufObjectID, sizeof(bufObjectID));
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
    LOGD(TAG, "Kose_API_ECDSAVerify");

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kKOSE_CLA, kKOSE_INS_VERIFY_SIGNATURE, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    
    uint8_t *pLc = &pCmdbuf[4]; // lc pointer
    uint8_t *pCmdOffset = &pCmdbuf[5];  // cmd data pointer
    uint8_t *pData = &pCmdbuf[5];   // total data pointer
    uint8_t bufObjectID[2] = {0};
    
    uint8_t bufDerSignHeader1[4] = {0x30, 0x44, 0x02, 0x20};   // sign der buffer
    uint8_t bufDerSignHeader2[2] = {0x02, 0x20};   // sign der buffer
    uint8_t bufDerSign[70] = {0};   // sign der buffer

    size_t totalSize = 0;
    
    uint32_to_buffer(objectID, 2, bufObjectID);
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));

    memcpy(bufDerSign, bufDerSignHeader1, sizeof(bufDerSignHeader1));
    memcpy(bufDerSign+4, signature, 32);
    memcpy(bufDerSign+36, bufDerSignHeader2, sizeof(bufDerSignHeader2));
    memcpy(bufDerSign+38, signature+32, 32);
    
    tlvDataSet_u8buf(&pData, &totalSize, kKOSE_TAG_KEYID, bufObjectID, 2); // Key ID
    tlvDataSet_u8buf(&pData, &totalSize, kKOSE_TAG_SHA256, inputData, inputDataLen); // Hash Data(SHA256)
    tlvDataSet_u8buf(&pData, &totalSize, kKOSE_TAG_SIGNATURE, bufDerSign, sizeof(bufDerSign)); // Signature by Server Private Key
    lvDataSet_u8buf(&pLc, &cmdbufLen, pCmdOffset, totalSize);
    cmdbufLen = sizeof(hdr.hdr) + cmdbufLen;
    
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        *presult = kKOSE_Result_SUCCESS;
    }
    else{
        *presult = kKOSE_Result_FAILURE;
    }

    return retStatus;
}

smStatus_t Kose_API_GetData(pKoseSession_t session_ctx, uint32_t objectID, uint8_t *data, size_t *pdataLen)
{
    LOGD(TAG, "Kose_API_GetData");

    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kKOSE_CLA, kKOSE_GET_DATA, kKOSE_P1_DEFAULT, kKOSE_P2_DEFAULT}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    uint8_t rspbuf[DATA_BUF_SIZE] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufTotalLen                  = 0;
    size_t rspIndex                        = 0;
    size_t rspDataIndex                    = 0;

    uint8_t bufObjectID[2] = {0};

    uint32_to_buffer(objectID, 2, bufObjectID);
    hdr.hdr[2] = bufObjectID[0];
    hdr.hdr[3] = bufObjectID[1];
    
    memcpy(pCmdbuf, hdr.hdr, sizeof(hdr.hdr));
    pCmdbuf[4] = 0x00;
    cmdbufLen = sizeof(hdr.hdr) + 1;

GetRes:
    retStatus = DoAPDUTxRx_s_Case2(session_ctx, cmdbuf, cmdbufLen, rspbuf, pdataLen);
    rspIndex = 0;     
    if (retStatus == SM_OK) {
        if(get_u8buf(pRspbuf, &rspIndex, *pdataLen - 2, data + (rspDataIndex), pdataLen) != 0)
        {
            *pdataLen = 0;
        }
        rspbufTotalLen += *pdataLen;
        *pdataLen = rspbufTotalLen;
    }
    else if((retStatus & 0xFF00) == SM_WRN_RESPONSE_DATA_INCOMPLETE) {
        if(get_u8buf(pRspbuf, &rspIndex, *pdataLen - 2, data + (rspDataIndex), pdataLen) != 0)
        {
            *pdataLen = 0;
        }
        rspbufTotalLen += *pdataLen;
        *pdataLen = rspbufTotalLen;

        rspDataIndex += rspIndex;
        memcpy(cmdbuf, (uint8_t*)"\x00\xC0\x00\x00\x00", 5);
        cmdbuf[4] = (uint8_t)(retStatus & 0x00FF);

        goto GetRes;
    }

    return retStatus;
}

#ifdef __cplusplus
}
#endif