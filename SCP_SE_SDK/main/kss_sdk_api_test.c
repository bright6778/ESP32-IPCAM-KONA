/* Copyright 2025 KONA
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <stdlib.h>

#include "kona_kss_api.h"
#include "kose_APDU_impl.h"
#include "kss_kose_uart.h"
#include "kona_kss_kose_types.h"
#include "kss_kose_mbedtls.h"
#include "kona_kss_debug.h"
#include "menu_define.h"
#include "kss_sdk_api_vector.h"

/* clang-format on */
#define KSS_PUBKEY_INDEX_CA                 0x0901
#define KSS_KEYPAIR_INDEX_CLIENT_PRIVATE    0x0100
#define KSS_KEYPAIR_INDEX_CLIENT_PUBLIC     0x0200
#define KSS_CERTIFICATE_INDEX               0x0701

static const char *TAG = "kss_sdk_api_test.c";

// uart variables
static kss_kose_uart_ctx_t se_uart_init;
static SE_Connect_Ctx_t se_conn_ctx;
                
// session variables
static kss_session_t session;
static kss_kose_session_t *kose_session;
static void *connectionData = NULL;
static kss_key_store_t keystore;

static void kss_print_buf(const char *title, const uint8_t *buf, int len)
{
    #define MAX_BUF_SIZE (128)
    char tmpbuf[MAX_BUF_SIZE + 8];
    int count = 0;
    count = sprintf(&tmpbuf[count], "%s = [", title);
    for (int i = 0; i < len; i++) {
        count += sprintf(&tmpbuf[count], i ? " %02x" : "%02x", buf[i]);
        if (count >= MAX_BUF_SIZE) {
            printf(TAG, "%s", tmpbuf);
            count = 0;
        }
    }
    if (count > 0) {
        printf(TAG, "%s](%d)", tmpbuf, len);
    }
    else {
        printf(TAG, "](%d)", len);
    }
}

void test_kss_session_open()
{
    kss_status_t kStatus = kStatus_KSS_Fail;
    smStatus_t status   = SM_NOT_OK; 

    LOGI(TAG, "Start kss_session_open");
    memset(&session, 0, sizeof(kss_session_t));
    set_se_uart_init_default(&se_uart_init);
    se_conn_ctx.connType = kType_SE_Conn_Type_UART;
    se_conn_ctx.conn_ctx = &se_uart_init;
    connectionData = &se_conn_ctx;
    kStatus = kss_session_open(&session, kType_KSS_SecureElement, 0, kKSS_ConnectionType_Plain, connectionData);
    if (kStatus_KSS_Success != kStatus) {
        LOGE(TAG, "kss_kose_session_open failed res : %d", kStatus);
    }
    kose_session = (kss_kose_session_t*)&session;
    LOGI(TAG, "End kss_session_open");
}

void test_kss_key_store_generate_key()
{
    LOGI(TAG, "Start " GENERATE_KEY);
    kss_object_t keyobject_ecc;
    
    uint8_t rst_data[256] = {0};
    size_t rst_data_len = 0;

    kss_status_t kStatus = kStatus_KSS_Fail;
    smStatus_t status   = SM_NOT_OK;

    size_t dataSize = 32;
    uint32_t keyId = 0x0100;
    uint32_t acl = 0x003200;
    
    test_kss_session_open();

    memset(&keystore, 0, sizeof(kss_key_store_t));

    LOGI(TAG, "Start kss_key_store_context_init");
    kStatus = kss_key_store_context_init(&keystore, &session);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init failed res : %d", kStatus);
        return;
    }

    /** Generate Key for ECC */
    LOGI(TAG, "Generate Key for ECC");
    LOGI(TAG, "Start kss_key_object_init");
    kStatus = kss_key_object_init(&keyobject_ecc, &keystore);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_object_init res : %d", kStatus);
        return;
    }

    LOGI(TAG, "Start kss_key_object_allocate_handle");
    kStatus = kss_key_object_allocate_handle(&keyobject_ecc, keyId, kKSS_KeyPart_Private, kKSS_CipherType_EC_NIST_P, dataSize, acl, kKeyObject_Mode_Persistent);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_object_allocate_handle failed res : %d", kStatus);
        return;
    }
    
    kStatus = kss_key_store_generate_key(&keystore, &keyobject_ecc, 256, kKOSE_Generate_ECC_Keypair, rst_data, &rst_data_len);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_store_generate_key failed res : %d", kStatus);
        return;
    }
    if(rst_data_len > 0){
        kss_debug_showframe(TAG, rst_data, rst_data_len);
    }

    LOGI(TAG, "End " GENERATE_KEY);

    return;
}

void test_KOSE_API_StoreData()
{
    LOGI(TAG, "Start " APDU_STORE_DATA);
    kss_object_t keyobject_ecc;
    kss_object_t keyobject_aes;
    kss_object_t keyobject_des;

    kss_status_t kStatus = kStatus_KSS_Fail;
    smStatus_t status   = SM_NOT_OK;

    size_t dataSize = 32;
    uint32_t keyId = 0x0700;
    uint32_t acl = 0x001032;
    
    test_kss_session_open();

    memset(&keystore, 0, sizeof(kss_key_store_t));

    uint8_t objectData[] = {0x30, 0x82, 0x02, 0xC2, 0x30, 0x82, 0x01, 0xAA, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x41,
                        0xF7, 0x79, 0xBA, 0xE7, 0x28, 0xE1, 0xC3, 0x88, 0xA7, 0xFC, 0x28, 0x16, 0xAD, 0x64, 0x46, 0xF9,
                        0xF1, 0x15, 0x0B, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
                        0x05, 0x00, 0x30, 0x4D, 0x31, 0x4B, 0x30, 0x49, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x42, 0x41,
                        0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x20, 0x57, 0x65, 0x62, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
                        0x65, 0x73, 0x20, 0x4F, 0x3D, 0x41, 0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x2E, 0x63, 0x6F, 0x6D, 0x20,
                        0x49, 0x6E, 0x63, 0x2E, 0x20, 0x4C, 0x3D, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6C, 0x65, 0x20, 0x53,
                        0x54, 0x3D, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x20, 0x43, 0x3D, 0x55,
                        0x53, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x35, 0x32, 0x36, 0x30, 0x32, 0x34, 0x35, 0x31,
                        0x30, 0x5A, 0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
                        0x5A, 0x30, 0x52, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4B, 0x52,
                        0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D,
                        0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x05,
                        0x4B, 0x6F, 0x6E, 0x61, 0x69, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x05,
                        0x4B, 0x6F, 0x6E, 0x61, 0x69, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x05};
    status = Kose_API_StoreData(&kose_session->s_ctx, keyId, acl, sizeof(objectData), 0x80, 0x00, objectData, sizeof(objectData));
    if(status != SM_OK){
        LOGE(TAG, APDU_STORE_DATA " return : 0x%X", status);
    }
    LOGI(TAG, "End %s", APDU_STORE_DATA);
}

void test_kss_symmetric_encrypt(){
    LOGI(TAG, "Start " API_KSS_SYMMETRIC_ENCRYPT);
    kss_object_t AES_object;
    kss_symmetric_t symAESCtx;
    kss_status_t kStatus = kStatus_KSS_Fail;
    
    test_kss_session_open();

    memset(&keystore, 0, sizeof(kss_key_store_t));

    // kss_key_store_context_init
    kStatus = kss_key_store_context_init(&keystore, &session);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init return : 0x%X", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start " API_KSS_SYMMETRIC_ENCRYPT " - AES Part");
    // AES Key object init
    kStatus = kss_key_object_init(&AES_object, &keystore);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init return : 0x%X", kStatus);
        goto ErrorExit;
    }

    // Allocate AES Key object handle
    kStatus = kss_key_object_allocate_handle(&AES_object, 0x0400, kKSS_KeyPart_Default, kKSS_CipherType_AES, sizeof(AES_Key_TestKeyVector), 0x000000, kKeyObject_Mode_Persistent);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_allocate_handle return : 0x%X", kStatus);
        goto ErrorExit;
    }

    // Initialize AES context
    kStatus = kss_symmetric_context_init(&symAESCtx, &session, &AES_object, kAlgorithm_KSS_AES_CBC);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_symmetric_context_init return : 0x%X", kStatus);
        goto ErrorExit;
    }

    uint8_t origin_data[sizeof(AES_Key_TestDataVector)] = {0};
    uint8_t rst_data[sizeof(AES_Key_TestDataVector)] = {0};
    size_t rst_data_len = 0;
    mempcpy(origin_data, AES_Key_TestDataVector, sizeof(AES_Key_TestDataVector));
    
    kStatus = kss_symmetric_encrypt(&symAESCtx, origin_data, sizeof(origin_data), rst_data, &rst_data_len);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, API_KSS_SYMMETRIC_ENCRYPT " return : 0x%X", kStatus);
        goto ErrorExit;
    }
    kss_print_buf("AES Encrypt Data", rst_data, rst_data_len);
ErrorExit :
    LOGI(TAG, "End " API_KSS_SYMMETRIC_ENCRYPT " - AES Part");
    kss_session_close(&session);
}

void test_kss_symmetric_decrypt(){
    LOGI(TAG, "Start " API_KSS_SYMMETRIC_DECRYPT);
    kss_object_t AES_object;
    kss_symmetric_t symAESCtx;
    kss_status_t kStatus = kStatus_KSS_Fail;
    
    test_kss_session_open();

    memset(&keystore, 0, sizeof(kss_key_store_t));

    // kss_key_store_context_init
    kStatus = kss_key_store_context_init(&keystore, &session);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init return : 0x%X", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start " API_KSS_SYMMETRIC_DECRYPT " - AES Part");
    // AES Key object init
    kStatus = kss_key_object_init(&AES_object, &keystore);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init return : 0x%X", kStatus);
        goto ErrorExit;
    }

    // Allocate AES Key object handle
    kStatus = kss_key_object_allocate_handle(&AES_object, 0x0401, kKSS_KeyPart_Default, kKSS_CipherType_AES, sizeof(AES_Key_TestKeyVector), 0x000000, kKeyObject_Mode_Persistent);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_allocate_handle return : 0x%X", kStatus);
        goto ErrorExit;
    }

    // Initialize AES context
    kStatus = kss_symmetric_context_init(&symAESCtx, &session, &AES_object, kAlgorithm_KSS_AES_CBC);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_symmetric_context_init return : 0x%X", kStatus);
        goto ErrorExit;
    }

    uint8_t origin_data[sizeof(AES_Key_TestDataVector)] = {0};
    uint8_t rst_data[sizeof(AES_Key_TestDataVector)] = {0};
    size_t rst_data_len = 0;
    mempcpy(origin_data, AES_Key_TestDataVector, sizeof(AES_Key_TestDataVector));
    
    kStatus = kss_symmetric_decrypt(&symAESCtx, origin_data, sizeof(origin_data), rst_data, &rst_data_len);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, API_KSS_SYMMETRIC_DECRYPT " return : 0x%X", kStatus);
        goto ErrorExit;
    }
    kss_print_buf("AES Decrypt Data", rst_data, rst_data_len);
ErrorExit :
    LOGI(TAG, "End " API_KSS_SYMMETRIC_DECRYPT " - AES Part");
    kss_session_close(&session);
}

void test_kss_key_store_erase_key()
{
    LOGI(TAG, "Start " API_ERASE_KEY);
    kss_object_t keyobject_aes;
    
    kss_status_t kStatus = kStatus_KSS_Fail;
    smStatus_t status   = SM_NOT_OK;

    size_t dataSize = 16;
    uint32_t keyId = 0x0400;
    uint32_t acl = 0x000000;
    
    test_kss_session_open();

    memset(&keystore, 0, sizeof(kss_key_store_t));

    LOGI(TAG, "Start kss_key_store_context_init");
    kStatus = kss_key_store_context_init(&keystore, &session);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init failed res : %d", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start kss_key_object_init - AES");
    kStatus = kss_key_object_init(&keyobject_aes, &keystore);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_object_init res : %d", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start kss_key_object_allocate_handle - AES");
    kStatus = kss_key_object_allocate_handle(&keyobject_aes, keyId, kKSS_KeyPart_Default, kKSS_CipherType_AES, dataSize, acl, kKeyObject_Mode_Persistent);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_object_allocate_handle failed res : %d", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start kss_key_store_set_key - AES");
    kStatus = kss_key_store_set_key(&keystore, &keyobject_aes, AES_Key_TestKeyVector, sizeof(AES_Key_TestKeyVector), 128, NULL, 0);
    if(kStatus != kStatus_KSS_Success){
        printf("kss_key_store_set_key failed res : %d\n", kStatus);
        goto ErrorExit;
    }

    /** Erase Key for AES */
    LOGI(TAG, "Start kss_key_store_erase_key - Key Type of Object ID / Physically delete");
    kStatus = kss_key_store_erase_key(&keystore, &keyobject_aes, 0x00);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_store_erase_key failed res : %d", kStatus);
        goto ErrorExit;
    }
    
    /** Put Key for AES */
    LOGI(TAG, "Start kss_key_store_set_key - AES");
    kStatus = kss_key_store_set_key(&keystore, &keyobject_aes, AES_Key_TestKeyVector, sizeof(AES_Key_TestKeyVector), 128, NULL, 0);
    if(kStatus != kStatus_KSS_Success){
        printf("kss_key_store_set_key failed res : %d\n", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start kss_key_store_erase_key - Key Type of Object ID / Logically delete");
    kStatus = kss_key_store_erase_key(&keystore, &keyobject_aes, 0x01);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_store_erase_key failed res : %d", kStatus);
        goto ErrorExit;
    }

    /** Put Key for AES */
    LOGI(TAG, "Start kss_key_store_set_key - AES");
    kStatus = kss_key_store_set_key(&keystore, &keyobject_aes, AES_Key_TestKeyVector, sizeof(AES_Key_TestKeyVector), 128, NULL, 0);
    if(kStatus != kStatus_KSS_Success){
        printf("kss_key_store_set_key failed res : %d\n", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start kss_key_store_erase_key - Object ID / Physically delete");
    kStatus = kss_key_store_erase_key(&keystore, &keyobject_aes, 0x00);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_store_erase_key failed res : %d", kStatus);
        goto ErrorExit;
    }

    /** Put Key for AES */
    LOGI(TAG, "Start kss_key_store_set_key - AES");
    kStatus = kss_key_store_set_key(&keystore, &keyobject_aes, AES_Key_TestKeyVector, sizeof(AES_Key_TestKeyVector), 128, NULL, 0);
    if(kStatus != kStatus_KSS_Success){
        printf("kss_key_store_set_key failed res : %d\n", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start kss_key_store_erase_key - Object ID / Logically delete");
    kStatus = kss_key_store_erase_key(&keystore, &keyobject_aes, 0x01);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_store_erase_key failed res : %d", kStatus);
        goto ErrorExit;
    }

ErrorExit :
    LOGI(TAG, "End " API_ERASE_KEY " - AES Part");
    kss_session_close(&session);
    return;
}

void test_kss_key_store_get_key()
{
    LOGI(TAG, "Start " API_GET_KEY);
    kss_object_t keyobject_aes;
    kss_object_t keyobject_ecc;
    
    kss_status_t kStatus = kStatus_KSS_Fail;
    smStatus_t status   = SM_NOT_OK;

    size_t dataSize = 16;
    uint32_t keyId = 0x0400;
    uint32_t acl = 0xFF0000;

    uint8_t bufData[DATA_BUF_SIZE];
    size_t  key_length = 0;
    
    test_kss_session_open();

    memset(&keystore, 0, sizeof(kss_key_store_t));

    LOGI(TAG, "Start kss_key_store_context_init");
    kStatus = kss_key_store_context_init(&keystore, &session);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init failed res : %d", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start kss_key_object_init - AES");
    kStatus = kss_key_object_init(&keyobject_aes, &keystore);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_object_init res : %d", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start kss_key_object_allocate_handle - AES");
    kStatus = kss_key_object_allocate_handle(&keyobject_aes, keyId, kKSS_KeyPart_Default, kKSS_CipherType_AES, dataSize, acl, kKeyObject_Mode_Persistent);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_object_allocate_handle failed res : %d", kStatus);
        goto ErrorExit;
    }

    LOGI(TAG, "Start kss_key_store_set_key - AES");
    kStatus = kss_key_store_set_key(&keystore, &keyobject_aes, AES_Key_TestKeyVector, sizeof(AES_Key_TestKeyVector), 128, NULL, 0);
    if(kStatus != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_set_key failed res : %d", kStatus);
        goto ErrorExit;
    }

    /** Get Key - AES */
    LOGI(TAG, "Start kss_key_store_get_key - AES");
    kStatus = kss_key_store_get_key(&keystore, &keyobject_aes, bufData, &key_length);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_store_get_key failed res : %d", kStatus);
        goto ErrorExit;
    }
    if(memcmp(AES_Key_TestKeyVector, bufData, key_length) != 0){
        LOGE(TAG, "kss_key_store_get_key wrong data! - AES");
        goto ErrorExit;
    }
    else{
        LOGI(TAG, "kss_key_store_get_key data - AES");
        kss_showframe(TAG, bufData, key_length);
    }

    ////////////////// ECC Key /////////////////////////
    // keyId = 0x0200;

    // LOGI(TAG, "Start kss_key_object_init - ECC");
    // kStatus = kss_key_object_init(&keyobject_ecc, &keystore);
    // if (kStatus != kStatus_KSS_Success) {
    //     LOGE(TAG, "kss_key_object_init res : %d", kStatus);
    //     goto ErrorExit;
    // }

    // LOGI(TAG, "Start kss_key_object_allocate_handle - ECC");
    // kStatus = kss_key_object_allocate_handle(&keyobject_ecc, keyId, kKSS_KeyPart_Public, kKSS_CipherType_EC_NIST_P, dataSize, acl, kKeyObject_Mode_Persistent);
    // if (kStatus != kStatus_KSS_Success) {
    //     LOGE(TAG, "kss_key_object_allocate_handle failed res : %d", kStatus);
    //     goto ErrorExit;
    // }

    // LOGI(TAG, "Start kss_key_store_set_key - ECC");
    // kStatus = kss_key_store_set_key(&keystore, &keyobject_ecc, ECC_PublicKey_TestVector, sizeof(ECC_PublicKey_TestVector), 512, NULL, 0);
    // if(kStatus != kStatus_KSS_Success){
    //     printf("kss_key_store_set_key failed res : %d\n", kStatus);
    //     goto ErrorExit;
    // }

    // /** Get Key - ECC */
    // LOGI(TAG, "Start kss_key_store_get_key - ECC Public Key");
    // kStatus = kss_key_store_get_key(&keystore, &keyobject_ecc, bufData, &key_length);
    // if (kStatus != kStatus_KSS_Success) {
    //     LOGE(TAG, "kss_key_store_get_key failed res : %d", kStatus);
    //     goto ErrorExit;
    // }
    // if(memcmp(ECC_PublicKey_TestVector, bufData, key_length) != 0){
    //     LOGE(TAG, "kss_key_store_get_key wrong data! - ECC Public Key");
    //     goto ErrorExit;
    // }
    // else{
    //     LOGI(TAG, "kss_key_store_get_key data - ECC Public Key");
    //     kss_showframe(TAG, bufData, key_length);
    // }

    LOGI(TAG, "Start kss_key_store_get_key_list");
    kStatus = kss_key_store_get_key_list(&keystore, bufData, &key_length);
    if (kStatus != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_store_get_key_list failed res : %d", kStatus);
        goto ErrorExit;
    }
    else{
        LOGI(TAG, "kss_key_store_get_key_list");
        kss_showframe(TAG, bufData, key_length);
    }

ErrorExit :
    LOGI(TAG, "Start kss_key_store_erase_key - Object ID / Physically delete");
    kStatus = kss_key_store_erase_key(&keystore, &keyobject_aes, 0x00);
    
    kss_session_close(&session);
    return;
}