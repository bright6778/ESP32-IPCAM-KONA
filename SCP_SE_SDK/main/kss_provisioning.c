/* Copyright 2025 KONA
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <stdlib.h>

#include "kona_kss_api.h"
#include "kss_kose_uart.h"
#include "kona_kss_kose_types.h"
#include "kss_kose_mbedtls.h"
#include "kona_kss_debug.h"

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

#define KSS_PUBKEY_INDEX_CA                 0x0901
#define KSS_KEYPAIR_INDEX_CLIENT_PRIVATE    0x0100
#define KSS_KEYPAIR_INDEX_CLIENT_PUBLIC     0x0200
#define KSS_CERTIFICATE_INDEX               0x0701

static const char *TAG = "kss_provisioning.c";

/*The size of the client certificate should be checked when script is used to store it in GP storage and updated here */
#define SIZE_CLIENT_CERTIFICATE 500

void se_provisioning(kss_session_t *session)
{
    LOGD(TAG, "se_provisioning start");
    
    kss_status_t status = kStatus_KSS_Fail;
    
    uint8_t client_key[2048];
    uint8_t client_cer[2048];

    uint8_t client_priv_key[32] = {0};
    uint8_t client_pub_key[65] = {0};
    
    // object var
    kss_object_t dev_keyobject_priv;    // device private key object
    //kss_object_t dev_cert;              // device cert object
    kss_object_t dev_keyobject_pub;     // device public key object
    size_t objectDataLen = 0;

    // keystore var
    kss_key_store_t keystore;
    
    memcpy(&client_key, &client_key_start, client_key_end - client_key_start);
    memcpy(&client_cer, &client_cert_start, client_cert_end - client_cert_start);
    
    // key store init
    memset(&keystore, 0, sizeof(kss_key_store_t));
    
    status = kss_key_store_context_init(&keystore, session);
    if(status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init failed res : %d", status);
        return;
    }

    //Provision the SE..

    // Device Private Key
    status = kss_key_object_init(&dev_keyobject_priv, &keystore);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_object_init for device privatekey Failed... status : %d", status);
        return;
    }

    // Unimplemented
    /*
    if(kss_mbedtls_parse_keyfile(client_key, client_key_end - client_key_start, client_priv_key, &objectDataLen) != 0){
        LOGE(TAG, " kss_mbedtls_parse_keyfile Failed...");
        return;
    }
    */

    // device private key for test
    objectDataLen = 32;
    mempcpy(client_priv_key, (uint8_t*)"\x75\x99\x1e\x33\x7c\x98\x5a\xaa\xbf\x87\x2d\x71\x8f\x7e\x86\xa9"
                                       "\x89\xe8\x29\x04\x77\xc8\xd9\xae\x20\x42\x8f\x5b\x29\x3e\x9b\x45", objectDataLen);

    status = kss_key_object_allocate_handle(&dev_keyobject_priv,
        KSS_KEYPAIR_INDEX_CLIENT_PRIVATE,
        kKSS_KeyPart_Private,
        kKSS_CipherType_EC_NIST_P,
        objectDataLen,
        0x003200,
        kKeyObject_Mode_Persistent);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, " kss_key_object_allocate_handle for privatekey Failed...\n");
        return;
    }
/*
    status = kss_key_store_set_key(&keystore, &dev_keyobject_priv, client_priv_key, objectDataLen, 256, NULL, 0);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, " kss_key_store_set_key  for privatekey Failed...\n");
        return;
    }
*/    
    // Device Public Key
    status = kss_key_object_init(&dev_keyobject_pub, &keystore);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, "kss_key_object_init for device publickey Failed... status : %d", status);
        return;
    }
    
    // Unimplemented
    /*
    objectDataLen = sizeof(client_pub_key);
    if(kss_mbedtls_parse_crt_getpublickey(client_cer, client_cert_end - client_cert_start, client_pub_key, &objectDataLen) != 0){
        LOGE(TAG, " kss_mbedtls_parse_keyfile publickey Failed...");
        return;
    }
    */
   
    // device public key for test
    objectDataLen = 65;
    mempcpy(client_pub_key, (uint8_t*)"\x04\x28\xf1\x67\x05\x63\x7d\x4d\x89\x20\x19\x72\xec\x1d\x49\x00\xe2"
                                      "\x97\x49\xe1\xa8\xb4\xe9\xc2\xfb\x72\x2d\xbe\xf5\xd0\x70\x4c\x5d"
                                      "\x2a\x58\x5e\xf2\x42\xcb\xf1\xf2\x8d\xb2\x9e\xd8\xe4\x5e\xc9\x4e"
                                      "\xf9\xfc\xd0\xa2\x78\xf0\x34\xff\x36\x20\x6b\x48\xc7\x2d\xbb\x62", objectDataLen);

    status = kss_key_object_allocate_handle(&dev_keyobject_pub,
        KSS_KEYPAIR_INDEX_CLIENT_PUBLIC,
        kKSS_KeyPart_Public,
        kKSS_CipherType_EC_NIST_P,
        objectDataLen,
        0x004410,
        kKeyObject_Mode_Persistent);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, " kss_key_object_allocate_handle for publickey Failed...\n");
        return;
    }
    
    LOGD(TAG, "objectDataLen : %d", objectDataLen);
    status = kss_key_store_set_key(&keystore, &dev_keyobject_pub, client_pub_key, objectDataLen, 256, NULL, 0);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, " kss_key_store_set_key  for keyPair Failed...\n");
        return;
    }
    /*
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
