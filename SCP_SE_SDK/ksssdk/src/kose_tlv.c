/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

  /** @file */
#ifdef __cplusplus
extern "C" {
#endif

#include <string.h> // memcpy
#include <limits.h>
#include <stdint.h>
#include "kose_enums.h"
#include "kona_kss_api.h"
#include "kose_tlv.h"
#include "kona_kss_debug.h"

#define KOSE_TLV_BUF_SIZE_CMD 255
#define KOSE_TLV_BUF_SIZE_RSP 2048

static const char *TAG = "kose_tlv.c";

int tlvSet_U8(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint8_t value)
{
    uint8_t *pBuf            = *buf;
    const size_t size_of_tlv = 1 + 1 + 1;
    if ((UINT_MAX - size_of_tlv) < (*bufLen)) {
        return 1;
    }
    if (((*bufLen) + size_of_tlv) > KOSE_TLV_BUF_SIZE_CMD) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 1;
    *pBuf++ = value;
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U16Optional(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint16_t value)
{
    if (value == 0) {
        return 0;
    }
    else {
        return tlvSet_U16(buf, bufLen, tag, value);
    }
}

int tlvSet_U16(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint16_t value)
{
    const size_t size_of_tlv = 1 + 1 + 2;
    uint8_t *pBuf            = *buf;
    if ((UINT_MAX - size_of_tlv) < (*bufLen)) {
        return 1;
    }
    if (((*bufLen) + size_of_tlv) > KOSE_TLV_BUF_SIZE_CMD) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 2;
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U32(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint32_t value)
{
    const size_t size_of_tlv = 1 + 1 + 4;
    uint8_t *pBuf            = *buf;
    if ((UINT_MAX - size_of_tlv) < (*bufLen)) {
        return 1;
    }
    if (((*bufLen) + size_of_tlv) > KOSE_TLV_BUF_SIZE_CMD) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 4;
    *pBuf++ = (uint8_t)((value >> 3 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 2 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U64_size(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint64_t value, uint16_t size)
{
    int8_t pos               = (uint8_t)size;
    const size_t size_of_tlv = 1 + 1 + size;
    uint8_t *pBuf            = *buf;
    if ((UINT_MAX - (*bufLen)) < size_of_tlv) {
        return 1;
    }
    if (((*bufLen) + size_of_tlv) > KOSE_TLV_BUF_SIZE_CMD) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = pos;
    pos--;
    for (; pos >= 0; pos--) {
        *pBuf++ = (uint8_t)((value >> pos * 8) & 0xFF);
    }
    *buf = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

//ISO 7816-4 Annex D.
int tlvGet_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, KOSE_TAG_t tag, uint8_t *rsp, size_t *pRspLen)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = 0;
    size_t extendedLen;
    size_t rspLen;
    //size_t len;

    if (rsp == NULL) {
        LOGD(TAG, "test1-1");
        goto cleanup;
    }

    if (pRspLen == NULL) {
        LOGD(TAG, "test1-2");
        goto cleanup;
    }
    if (bufLen < 2) {
        LOGD(TAG, "test1-3");
        goto cleanup;
    }
    if ((*pBufIndex) > (bufLen - 2) /* Tag + len */) {
        LOGD(TAG, "test1-4");
        goto cleanup;
    }

    got_tag = *pBuf++;
    if (got_tag != tag) {
        LOGD(TAG, "test1-5");
        goto cleanup;
    }
    rspLen = *pBuf++;

    LOGD(TAG, "test1");

    if (rspLen <= 0x7FU) {
        extendedLen = rspLen;
        *pBufIndex += (1 + 1);
    }
    else if (rspLen == 0x81) {
        if ((*pBufIndex) > (bufLen - 3) /* Ext len */) {
            LOGD(TAG, "test2");
            goto cleanup;
        }
        extendedLen = *pBuf++;
        *pBufIndex += (1 + 1 + 1);
    }
    else if (rspLen == 0x82) {
        if ((*pBufIndex) > (bufLen - 4) /* Ext len */) {
            LOGD(TAG, "test3");
            goto cleanup;
        }
        extendedLen = *pBuf++;
        extendedLen = (extendedLen << 8) | *pBuf++;
        *pBufIndex += (1 + 1 + 2);
    }
    else {
        LOGD(TAG, "test4");
        goto cleanup;
    }

    if (extendedLen > *pRspLen) {
        LOGD(TAG, "test5");
        goto cleanup;
    }
    if (extendedLen > (bufLen - *pBufIndex)) {
        LOGD(TAG, "test6");
        goto cleanup;
    }

    *pRspLen = extendedLen;
    *pBufIndex += extendedLen;
    while (extendedLen-- > 0) {
        *rsp++ = *pBuf++;
    }
    retVal = 0;
cleanup:
    if (retVal != 0) {
        if (pRspLen != NULL) {
            *pRspLen = 0;
        }
    }
    return retVal;
}

int tlvDataSet_u8buf(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    uint8_t *pBuf = *buf;

    /* if < 0x7F
    *    len = 1 byte
    * elif if < 0xFF
    *    '0x81' + len == 2 Bytes
    * elif if < 0xFFFF
    *    '0x82' + len_msb + len_lsb == 3 Bytes
    */
    const size_t size_of_length = (cmdLen <= 0x7f ? 1 : (cmdLen <= 0xFf ? 2 : 3));
    const size_t size_of_tlv    = size_of_length + cmdLen + 1;
    
    if ((UINT_MAX - (*bufLen)) < size_of_tlv) {
        return 1;
    }

    if (((*bufLen) + size_of_tlv) > KOSE_TLV_BUF_SIZE_CMD) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    
    if (cmdLen <= 0x7Fu) {
        *pBuf++ = (uint8_t)cmdLen;
    }
    else if (cmdLen <= 0xFFu) {
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else if (cmdLen <= 0xFFFFu) {
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 1 * 8) & 0xFF);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else {
        return 1;
    }
    if ((cmdLen > 0) && (cmd != NULL)) {
        while (cmdLen-- > 0) {
            *pBuf++ = *cmd++;
        }
    }

    *buf = pBuf;
    
    *bufLen += size_of_tlv;
    return 0;
}

int tlvDataSet_u8buf_len2byte(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    uint8_t *pBuf = *buf;

    const size_t size_of_length = 2;
    const size_t size_of_tlv    = size_of_length + cmdLen + 1;
    
    if ((UINT_MAX - (*bufLen)) < size_of_tlv) {
        return 1;
    }

    if (((*bufLen) + size_of_tlv) > KOSE_TLV_BUF_SIZE_CMD) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    
    if (cmdLen <= 0xFFFFu) {
        *pBuf++ = (uint8_t)((cmdLen >> 1 * 8) & 0xFF);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else {
        return 1;
    }
    if ((cmdLen > 0) && (cmd != NULL)) {
        while (cmdLen-- > 0) {
            *pBuf++ = *cmd++;
        }
    }

    *buf = pBuf;
    
    *bufLen += size_of_tlv;
    return 0;
}

int lvDataSet_u8buf(uint8_t **buf, size_t *bufLen, const uint8_t *cmd, size_t cmdLen)
{
    uint8_t *pBuf = *buf;

    const size_t size_of_length = 1;
    const size_t size_of_tlv    = size_of_length + cmdLen;
    
    if ((UINT_MAX - (*bufLen)) < size_of_tlv) {
        return 1;
    }

    if (((*bufLen) + size_of_tlv) > KOSE_TLV_BUF_SIZE_CMD) {
        return 1;
    }
    
    *pBuf++ = (uint8_t)cmdLen;

    if ((cmdLen > 0) && (cmd != NULL)) {
        while (cmdLen-- > 0) {
            *pBuf++ = *cmd++;
        }
    }

    *buf = pBuf;
    
    *bufLen += size_of_tlv;
    return 0;
}

int DataSet_u8buf(uint8_t **buf, const uint8_t *data, size_t dataLen)
{
    uint8_t *pBuf = *buf;

    if (UINT_MAX < dataLen) {
        return 1;
    }

    if ((dataLen > 0) && (data != NULL)) {
        while (dataLen-- > 0) {
            *pBuf++ = *data++;
        }
    }

    *buf = pBuf;
    return 0;
}

int get_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint8_t *rsp, size_t *pRspLen)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    size_t rspLen = bufLen;

    if(rspLen > KOSE_TLV_BUF_SIZE_RSP - 2){
        return retVal;
    }

    *pRspLen = rspLen;
    while (rspLen-- > 0) {
        *rsp++ = *pBuf++;
    }
    *pBufIndex += *pRspLen;
    retVal = 0;
    return retVal;
}

smStatus_t DoAPDUTx_s_Case3(KoseSession_t *pSessionCtx, uint8_t *cmdBuf, size_t cmdBufLen)
{
    uint8_t rxBuf[KOSE_TLV_BUF_SIZE_RSP + 2] = {0};
    size_t rxBufLen                           = sizeof(rxBuf);
    smStatus_t apduStatus                     = SM_NOT_OK;

    if (pSessionCtx == NULL) {
        return apduStatus;
    }

    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
#ifdef CONNECT_SE_I2C //I2C의 경우 가변으로 최대 32byte까지 받아옴.
        rxBufLen = 0;
#endif
        apduStatus = pSessionCtx->fp_TXn(pSessionCtx, cmdBuf, cmdBufLen, rxBuf, &rxBufLen);
    }
    return apduStatus;
}

smStatus_t DoAPDUTxRx_s_Case2(KoseSession_t *pSessionCtx, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rspBuf, size_t *pRspBufLen)
{
    smStatus_t apduStatus;

    if (pSessionCtx == NULL) {
        return SM_NOT_OK;
    }

    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
        apduStatus = pSessionCtx->fp_TXn(pSessionCtx, cmdBuf, cmdBufLen, rspBuf, pRspBufLen);
    }
    return apduStatus;
}

smStatus_t DoAPDUTxRx_s_Case4(KoseSession_t *pSessionCtx, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rspBuf, size_t *pRspBufLen)
{
    smStatus_t apduStatus;
    if (pSessionCtx == NULL) {
        return SM_NOT_OK;
    }

    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
        apduStatus = pSessionCtx->fp_TXn(pSessionCtx, cmdBuf, cmdBufLen, rspBuf, pRspBufLen);
    }
    return apduStatus;
}

#ifdef __cplusplus
}
#endif
