#pragma once

#ifndef __KSS_MBEDTLS_H
#define __KSS_MBEDTLS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

//#include "kona_kss_kose_config.h"
//#include "kose_tlv.h"
//#include "kss_kose_uart.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"

#include "kona_kss_mbedtls_types.h"

#ifdef DEBUG_PRINT
#include "esp_log.h"
#include "debug.h"
#endif

static kss_status_t kss_mbedtls_set_key(
    kss_mbedtls_object_t *keyObject, const uint8_t *data, size_t dataLen, size_t keyBitLen);

void cp_tls_register_with_mbedtls(mbedtls_ssl_config *config);

kss_status_t kss_mbedtls_key_object_init(kss_mbedtls_object_t *keyObject, kss_mbedtls_key_store_t *keyStore);

kss_status_t kss_mbedtls_key_object_allocate_handle(
    kss_mbedtls_object_t *keyObject, uint32_t keyId, kss_key_part_t key_part, kss_cipher_type_t cipherType, size_t keyByteLenMax, uint32_t options);

kss_status_t kss_mbedtls_key_store_context_init(kss_mbedtls_key_store_t *keyStore, kss_mbedtls_session_t *session);

kss_status_t kss_mbedtls_key_store_allocate(kss_mbedtls_key_store_t *keyStore, uint32_t keyStoreId); 

kss_status_t kss_mbedtls_asymmetric_context_init(
    kss_mbedtls_asymmetric_t *context, kss_mbedtls_session_t *session, kss_mbedtls_object_t *keyObject, kss_algorithm_t algorithm, kss_mode_t mode);

kss_status_t kss_mbedtls_asymmetric_sign_digest(
    kss_mbedtls_asymmetric_t *context, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

#ifdef __cplusplus
}
#endif
#endif /* MBEDTLS_H */