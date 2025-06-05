/* Copyright 2025 KONA
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <stdlib.h>

#include "kona_kss_api.h"
#include "kss_kose_uart.h"
#include "kona_kss_kose_types.h"
#include "kss_kose_mbedtls.h"
#include "debug.h"

/* clang-format off */

extern const char client_cert_start[] asm("_binary_client_crt_start");
extern const char client_cert_end[] asm("_binary_client_crt_end");
extern const char client_key_start[] asm("_binary_client_key_start");
extern const char client_key_end[] asm("_binary_client_key_end");
extern const char root_cert_auth_start[]   asm("_binary_root_cert_auth_crt_start");
extern const char root_cert_auth_end[]   asm("_binary_root_cert_auth_crt_end");
extern const char root_cert_auth_ecc_start[]   asm("_binary_root_cert_auth_ecc_crt_start");
extern const char root_cert_auth_ecc_end[]   asm("_binary_root_cert_auth_ecc_crt_end");

/* clang-format on */

#define KSS_PUBKEY_INDEX_CA 0x0900
#define KSS_KEYPAIR_INDEX_CLIENT_PRIVATE 0x0100
#define KSS_CERTIFICATE_INDEX 0x0700

static const char *TAG = "kss_provisioning.c";

/*The size of the client certificate should be checked when script is used to store it in GP storage and updated here */
#define SIZE_CLIENT_CERTIFICATE 500

void se_provisioning(kss_session_t *session)
{
    LOGD(TAG, "se_provisioning start");
    
    kss_status_t status = kStatus_KSS_Fail;
    
    const uint8_t client_key[2048];
    const uint8_t rootca_key[2048];
    const uint8_t client_cer[2048];

    uint8_t client_priv_key[32] = {0};
    uint8_t client_pub_key[64] = {0};
    
    // object var
    kss_object_t keyobject; // device private key object
    //kss_object_t dev_cert;  // device cert object
    //kss_object_t pub_obj;   // CA cert object
    size_t objectDataLen = 0;

    // keystore var
    kss_key_store_t keystore;
    
    memcpy(&client_key, &client_key_start, client_key_end - client_key_start);
    memcpy(&client_cer, &client_cert_start, client_cert_end - client_cert_start);
    memcpy(&rootca_key, &root_cert_auth_start, root_cert_auth_end - root_cert_auth_start);
    
    // key store init
    memset(&keystore, 0, sizeof(kss_key_store_t));
    
    status = kss_key_store_context_init(&keystore, session);
    if(status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init failed res : %d", status);
        return;
    }

    //Provision the SE..
    status = kss_key_object_init(&keyobject, &keystore);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_object_init for device privatgekey Failed... status : %d", status);
        return;
    }

    status = kss_key_object_allocate_handle(&keyobject,
        (uint32_t)(KSS_KEYPAIR_INDEX_CLIENT_PRIVATE | 0x0001),
        kKSS_KeyPart_Private,
        kKSS_CipherType_EC_NIST_P,
        client_key_end - client_key_start,
        0x003200,
        kKeyObject_Mode_Persistent);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, " kss_key_object_allocate_handle for keyPair Failed...\n");
        return;
    }

    if(kss_mbedtls_parse_keyfile(client_key, client_key_end - client_key_start, client_priv_key, &objectDataLen) != 0){
        LOGE(TAG, " kss_mbedtls_parse_keyfile Failed...");
        return;
    }
    
    status = kss_key_store_set_key(&keystore, &keyobject, client_priv_key, objectDataLen, 256, NULL, 0);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, " kss_key_store_set_key  for keyPair Failed...\n");
        return;
    }

    /*
    status = kss_key_object_init(&gKSSExCtx.extPubkey, &pCtx->ks);
    if (status != kStatus_KSS_Success) {
        printf(" kss_key_object_init for Pub key Failed...\n");
        return;
    }

    status = kss_key_object_allocate_handle(&gKSSExCtx.extPubkey,
        KSS_PUBKEY_INDEX_CA,
        kKSS_KeyPart_Public,
        kKSS_CipherType_EC_NIST_P,
        sizeof(rootca_key),
        kKeyObject_Mode_Persistent);
    if (status != kStatus_KSS_Success) {
        printf(" kss_key_object_allocate_handle for Pub key Failed...\n");
        return;
    }

    status = kss_key_store_set_key(&pCtx->ks, &gKSSExCtx.extPubkey, rootca_key, sizeof(rootca_key), 256, NULL, 0);
    if (status != kStatus_KSS_Success) {
        printf(" kss_key_store_set_key for Pub key Failed...\n");
        return;
    }

    status = kss_key_object_init(&gKSSExCtx.clientCert, &pCtx->ks);
    if (status != kStatus_KSS_Success) {
        printf(" kss_key_object_init for Pub key Failed...\n");
        return;
    }

    status = kss_key_object_allocate_handle(&gKSSExCtx.clientCert,
        KSS_CERTIFICATE_INDEX,
        kKSS_KeyPart_Default,
        kKSS_CipherType_Binary,
        sizeof(client_cer),
        kKeyObject_Mode_Persistent);
    if (status != kStatus_KSS_Success) {
        printf(" kss_key_object_allocate_handle Failed!!!");
        return;
    }

    status = kss_key_store_set_key(
        &pCtx->ks, &gKSSExCtx.clientCert, client_cer, sizeof(client_cer), sizeof(client_cer) * 8, NULL, 0);
    if (status != kStatus_KSS_Success) {
        printf(" Store Certificate Failed!!!");
        return;
    }
*/

    return;
}
