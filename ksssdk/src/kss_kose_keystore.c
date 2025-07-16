/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

/** @file */
#ifdef __cplusplus
extern "C" {
#endif

#include "kona_kss_api.h"
#include "kona_kss_ftr_default.h"
#include "kose_APDU_impl.h"
#include "ensure.h"
#include "kona_kss_util_asn1_der.h"
#include "kona_kss_policy.h"
#include "ecdsa_verify_alt.h"
#include "kss_kose_keystore.h"
#include "kona_kss_debug.h"

static const char *TAG = "kss_kose_keystore.c";

#define ADD_DER_ECC_NISTP192_HEADER(x) ((x) + der_ecc_nistp192_header_len)
#define REMOVE_DER_ECC_NISTP192_HEADER(x) ((x)-der_ecc_nistp192_header_len)

#define ADD_DER_ECC_NISTP224_HEADER(x) ((x) + der_ecc_nistp224_header_len)
#define REMOVE_DER_ECC_NISTP224_HEADER(x) ((x)-der_ecc_nistp224_header_len)

#define ADD_DER_ECC_NISTP256_HEADER(x) ((x) + der_ecc_nistp256_header_len)
#define REMOVE_DER_ECC_NISTP256_HEADER(x) ((x)-der_ecc_nistp256_header_len)

#define ADD_DER_ECC_NISTP384_HEADER(x) ((x) + der_ecc_nistp384_header_len)
#define REMOVE_DER_ECC_NISTP384_HEADER(x) ((x)-der_ecc_nistp384_header_len)

#define ADD_DER_ECC_NISTP521_HEADER(x) ((x) + der_ecc_nistp521_header_len)
#define REMOVE_DER_ECC_NISTP521_HEADER(x) ((x)-der_ecc_nistp521_header_len)

#define ADD_DER_ECC_160K_HEADER(x) ((x) + der_ecc_160k_header_len)
#define REMOVE_DER_ECC_160K_HEADER(x) ((x)-der_ecc_160k_header_len)

#define ADD_DER_ECC_192K_HEADER(x) ((x) + der_ecc_192k_header_len)
#define REMOVE_DER_ECC_192K_HEADER(x) ((x)-der_ecc_192k_header_len)

#define ADD_DER_ECC_224K_HEADER(x) ((x) + der_ecc_224k_header_len)
#define REMOVE_DER_ECC_224K_HEADER(x) ((x)-der_ecc_224k_header_len)

#define ADD_DER_ECC_256K_HEADER(x) ((x) + der_ecc_256k_header_len)
#define REMOVE_DER_ECC_256K_HEADER(x) ((x)-der_ecc_256k_header_len)

#define ADD_DER_ECC_BP160_HEADER(x) ((x) + der_ecc_bp160_header_len)
#define REMOVE_DER_ECC_BP160_HEADER(x) ((x)-der_ecc_bp160_header_len)

#define ADD_DER_ECC_BP192_HEADER(x) ((x) + der_ecc_bp192_header_len)
#define REMOVE_DER_ECC_BP192_HEADER(x) ((x)-der_ecc_bp192_header_len)

#define ADD_DER_ECC_BP224_HEADER(x) ((x) + der_ecc_bp224_header_len)
#define REMOVE_DER_ECC_BP224_HEADER(x) ((x)-der_ecc_bp224_header_len)

#define ADD_DER_ECC_BP320_HEADER(x) ((x) + der_ecc_bp320_header_len)
#define REMOVE_DER_ECC_BP320_HEADER(x) ((x)-der_ecc_bp320_header_len)

#define ADD_DER_ECC_BP384_HEADER(x) ((x) + der_ecc_bp384_header_len)
#define REMOVE_DER_ECC_BP384_HEADER(x) ((x)-der_ecc_bp384_header_len)

#define ADD_DER_ECC_BP256_HEADER(x) ((x) + der_ecc_bp256_header_len)
#define REMOVE_DER_ECC_BP256_HEADER(x) ((x)-der_ecc_bp256_header_len)

#define ADD_DER_ECC_BP512_HEADER(x) ((x) + der_ecc_bp512_header_len)
#define REMOVE_DER_ECC_BP512_HEADER(x) ((x)-der_ecc_bp512_header_len)

#define ADD_DER_ECC_MONT_DH_448_HEADER(x) ((x) + der_ecc_mont_dh_448_header_len)
#define REMOVE_DER_ECC_MONT_DH_448_HEADER(x) ((x)-der_ecc_mont_dh_448_header_len)
#define ADD_DER_ECC_MONT_DH_25519_HEADER(x) ((x) + der_ecc_mont_dh_25519_header_len)
#define REMOVE_DER_ECC_MONT_DH_25519_HEADER(x) ((x)-der_ecc_mont_dh_25519_header_len)

#define ADD_DER_ECC_TWISTED_ED_25519_HEADER(x) ((x) + der_ecc_twisted_ed_25519_header_len)
#define REMOVE_DER_ECC_TWISTED_ED_25519_HEADER(x) ((x)-der_ecc_twisted_ed_25519_header_len)

#define CONVERT_BYTE(x) ((x) / 8)
#define CONVERT_BIT(x) ((x)*8)

void add_ecc_header(uint8_t *key, size_t *keylen, uint8_t **key_buf, size_t *key_buflen, uint32_t curve_id)
{
    if (key == NULL || key_buf == NULL || key_buflen == NULL) {
        goto exit;
    }
#if KSSFTR_KOSE_KEY_SET
    if (curve_id == kKOSE_ECCurve_NIST_P256) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_nistp256_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_nistp256_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_nist256, der_ecc_nistp256_header_len);
        *key_buf    = ADD_DER_ECC_NISTP256_HEADER(key);
        *key_buflen = ADD_DER_ECC_NISTP256_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_NIST_P384) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_nistp384_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_nistp384_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_nist384, der_ecc_nistp384_header_len);
        *key_buf    = ADD_DER_ECC_NISTP384_HEADER(key);
        *key_buflen = ADD_DER_ECC_NISTP384_HEADER(*key_buflen);
    }
#if KSS_HAVE_EC_NIST_192
    else if (curve_id == kKOSE_ECCurve_NIST_P192) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_nistp192_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_nistp192_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_nist192, der_ecc_nistp192_header_len);
        *key_buf    = ADD_DER_ECC_NISTP192_HEADER(key);
        *key_buflen = ADD_DER_ECC_NISTP192_HEADER(*key_buflen);
    }
#endif
#if KSS_HAVE_EC_NIST_224
    else if (curve_id == kKOSE_ECCurve_NIST_P224) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_nistp224_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_nistp224_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_nist224, der_ecc_nistp224_header_len);
        *key_buf    = ADD_DER_ECC_NISTP224_HEADER(key);
        *key_buflen = ADD_DER_ECC_NISTP224_HEADER(*key_buflen);
    }
#endif
#if KSS_HAVE_EC_NIST_521
    else if (curve_id == kKOSE_ECCurve_NIST_P521) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_nistp521_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_nistp521_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_nist521, der_ecc_nistp521_header_len);
        *key_buf    = ADD_DER_ECC_NISTP521_HEADER(key);
        *key_buflen = ADD_DER_ECC_NISTP521_HEADER(*key_buflen);
    }
#endif
#if KSS_HAVE_EC_BP
    else if (curve_id == kKOSE_ECCurve_Brainpool160) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_bp160_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_bp160_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_bp160, der_ecc_bp160_header_len);
        *key_buf    = ADD_DER_ECC_BP160_HEADER(key);
        *key_buflen = ADD_DER_ECC_BP160_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_Brainpool192) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_bp192_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_bp192_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_bp192, der_ecc_bp192_header_len);
        *key_buf    = ADD_DER_ECC_BP192_HEADER(key);
        *key_buflen = ADD_DER_ECC_BP192_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_Brainpool224) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_bp224_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_bp224_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_bp224, der_ecc_bp224_header_len);
        *key_buf    = ADD_DER_ECC_BP224_HEADER(key);
        *key_buflen = ADD_DER_ECC_BP224_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_Brainpool320) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_bp320_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_bp320_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_bp320, der_ecc_bp320_header_len);
        *key_buf    = ADD_DER_ECC_BP320_HEADER(key);
        *key_buflen = ADD_DER_ECC_BP320_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_Brainpool384) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_bp384_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_bp384_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_bp384, der_ecc_bp384_header_len);
        *key_buf    = ADD_DER_ECC_BP384_HEADER(key);
        *key_buflen = ADD_DER_ECC_BP384_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_Brainpool256) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_bp256_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_bp256_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_bp256, der_ecc_bp256_header_len);
        *key_buf    = ADD_DER_ECC_BP256_HEADER(key);
        *key_buflen = ADD_DER_ECC_BP256_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_Brainpool512) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_bp512_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_bp512_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_bp512, der_ecc_bp512_header_len);
        *key_buf    = ADD_DER_ECC_BP512_HEADER(key);
        *key_buflen = ADD_DER_ECC_BP512_HEADER(*key_buflen);
    }
#endif
#if KSS_HAVE_EC_NIST_K
    else if (curve_id == kKOSE_ECCurve_Secp256k1) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_256k_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_256k_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_256k, der_ecc_256k_header_len);
        *key_buf    = ADD_DER_ECC_256K_HEADER(key);
        *key_buflen = ADD_DER_ECC_256K_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_Secp160k1) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_160k_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_160k_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_160k, der_ecc_160k_header_len);
        *key_buf    = ADD_DER_ECC_160K_HEADER(key);
        *key_buflen = ADD_DER_ECC_160K_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_Secp192k1) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_192k_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_192k_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_192k, der_ecc_192k_header_len);
        *key_buf    = ADD_DER_ECC_192K_HEADER(key);
        *key_buflen = ADD_DER_ECC_192K_HEADER(*key_buflen);
    }
    else if (curve_id == kKOSE_ECCurve_Secp224k1) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_224k_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_224k_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_224k, der_ecc_224k_header_len);
        *key_buf    = ADD_DER_ECC_224K_HEADER(key);
        *key_buflen = ADD_DER_ECC_224K_HEADER(*key_buflen);
    }
#endif
#if KSS_HAVE_EC_MONT
#if KSS_HAVE_KOSE_VER_GTE_07_02
    else if (curve_id == kKOSE_ECCurve_ECC_MONT_DH_448) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_mont_dh_448_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_mont_dh_448_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_mont_dh_448, der_ecc_mont_dh_448_header_len);
        *key_buf    = ADD_DER_ECC_MONT_DH_448_HEADER(key);
        *key_buflen = ADD_DER_ECC_MONT_DH_448_HEADER(*key_buflen);
    }
#endif
    else if (curve_id == kKOSE_ECCurve_ECC_MONT_DH_25519) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_mont_dh_25519_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_mont_dh_25519_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_mont_dh_25519, der_ecc_mont_dh_25519_header_len);
        *key_buf    = ADD_DER_ECC_MONT_DH_25519_HEADER(key);
        *key_buflen = ADD_DER_ECC_MONT_DH_25519_HEADER(*key_buflen);
    }
#endif // KSS_HAVE_EC_MONT
#if KSS_HAVE_EC_ED
    else if (curve_id == kKOSE_ECCurve_ECC_ED_25519) {
        ENSURE_OR_GO_EXIT((*keylen) > der_ecc_twisted_ed_25519_header_len);
        ENSURE_OR_GO_EXIT((SIZE_MAX - der_ecc_twisted_ed_25519_header_len) >= (*key_buflen));
        memcpy(key, gecc_der_header_twisted_ed_25519, der_ecc_twisted_ed_25519_header_len);
        *key_buf    = ADD_DER_ECC_TWISTED_ED_25519_HEADER(key);
        *key_buflen = ADD_DER_ECC_TWISTED_ED_25519_HEADER(*key_buflen);
    }
#endif
    else {
        LOGI(TAG, "Returned is not in DER Format");
        *key_buf    = key;
        *key_buflen = 0;
    }
#endif
exit:
    return;
}

/* ************************************************************************** */
/* Functions : kss_kose_keystore                                             */
/* ************************************************************************** */

kss_status_t kss_kose_key_store_context_init(kss_kose_key_store_t *keyStore, kss_kose_session_t *session)
{
    kss_status_t retval = kStatus_KSS_Success;
    if (keyStore == NULL) {
        return kStatus_KSS_Fail;
    }
    memset(keyStore, 0, sizeof(*keyStore));
    keyStore->session = session;
    return retval;
}

kss_status_t kss_kose_key_store_allocate(kss_kose_key_store_t *keyStore, uint32_t keyStoreId)
{
    AX_UNUSED_ARG(keyStore);
    AX_UNUSED_ARG(keyStoreId);
    return kStatus_KSS_Success;
}

void kss_kose_set_kss_keystore(kss_key_store_t *ksskeystore)
{
    kss_mbedtls_set_kss_keystore(ksskeystore);
}

void kss_kose_key_store_context_free(kss_kose_key_store_t *keyStore)
{
    memset(keyStore, 0, sizeof(*keyStore));
}

kss_status_t kss_kose_key_store_get_data(
    kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject, uint8_t *data, size_t *dataLen)
{
    kss_status_t retval           = kStatus_KSS_Fail;
    kss_cipher_type_t cipher_type = kKSS_CipherType_NONE;
    smStatus_t status             = SM_NOT_OK;
    ENSURE_OR_GO_EXIT(keyObject);
    ENSURE_OR_GO_EXIT(data);
    ENSURE_OR_GO_EXIT(dataLen);
    cipher_type = (kss_cipher_type_t)keyObject->cipherType;

    switch (cipher_type) {
    case kKSS_CipherType_EC_NIST_P:
#if KSS_HAVE_EC_NIST_K
    case kKSS_CipherType_EC_NIST_K:
#endif
#if KSS_HAVE_EC_BP
    case kKSS_CipherType_EC_BRAINPOOL:
#endif
#if KSS_HAVE_EC_MONT
    case kKSS_CipherType_EC_MONTGOMERY:
#endif
#if KSS_HAVE_EC_ED
    case kKSS_CipherType_EC_TWISTED_ED:
#endif
    {
        /* Return the Key length including the ECC DER Header */
        /*
        add_ecc_header(key, keylen, &key_buf, &key_buflen, keyObject->curve_id);
        ENSURE_OR_GO_EXIT(*keylen > key_buflen);
        (*keylen) = (*keylen) - key_buflen;
        */

        status = Kose_API_GetData(&keyStore->session->s_ctx, keyObject->keyId, data, dataLen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);

        /* Change Endiannes. */
        /*
#if KSS_HAVE_EC_MONT || KSS_HAVE_EC_ED
        if ((keyObject->curve_id == kKOSE_ECCurve_ECC_MONT_DH_25519) ||
            (keyObject->curve_id == kKOSE_ECCurve_ECC_MONT_DH_448) ||
            (keyObject->curve_id == kKOSE_ECCurve_ECC_ED_25519)) {
            for (size_t keyValueIdx = 0; keyValueIdx < (*dataLen >> 1); keyValueIdx++) {
                uint8_t swapByte                   = key_buf[keyValueIdx];
                key_buf[keyValueIdx]               = key_buf[*dataLen - 1 - keyValueIdx];
                key_buf[*dataLen - 1 - keyValueIdx] = swapByte;
            }
        }
#endif
        */
        /* Return the Key length with header length */
        //*dataLen += key_buflen;

        break;
    }
    default:
        goto exit;
    }

    retval = kStatus_KSS_Success;
exit:
    return retval;
}

#if 0 
static kss_status_t kss_kose_key_store_set_ecc_public_key(kss_kose_key_store_t *keyStore,
    kss_kose_object_t *keyObject,
    const uint8_t *key,
    size_t keyLen,
    size_t keyBitLen,
    void *policy_buff,
    size_t policy_buff_len)
{
    kss_status_t retval     = kStatus_KSS_Fail;

    kss_status_t asn_retval = kStatus_KSS_Fail;
    smStatus_t status       = SM_NOT_OK;
    KosePolicy_t kose_policy;
    KOSE_INS_t transient_type;
    KOSE_ECCurve_t curveId    = keyObject->curve_id;
    KOSE_KeyPart_t key_part   = kKOSE_KeyPart_NA;
    KOSE_Result_t exists      = kKOSE_Result_NA;
    KOSE_ECCurve_t retCurveId = keyObject->curve_id;
    size_t std_pubKey_len      = 0;
    size_t std_privKey_len     = 0;
#if KSS_HAVE_EC_MONT || KSS_HAVE_EC_ED
    uint8_t pubKeyReversed[64] = {
        0,
    };
#endif
    const uint8_t *pPublicKey = NULL;
    size_t publicKeyLen       = 0;
    uint16_t publicKeyIndex   = 0;

    /* Assign proper instruction type based on keyObject->isPersistant  */
    (keyObject->isPersistant) ? (transient_type = kKOSE_INS_NA) : (transient_type = kKOSE_INS_TRANSIENT);

    kose_policy.value     = (uint8_t *)policy_buff;
    kose_policy.value_len = policy_buff_len;

    if (keyObject->curve_id == 0) {
        keyObject->curve_id =
            (KOSE_ECCurve_t)kose_kssKeyTypeLenToCurveId((kss_cipher_type_t)keyObject->cipherType, keyBitLen);
    }

    if (keyObject->curve_id <= 0) {
        goto exit;
    }

    status = kss_kose_create_curve_if_needed(&keyObject->keyStore->session->s_ctx, keyObject->curve_id);
    if (status == SM_NOT_OK) {
        goto exit;
    }
    else if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
        goto exit;
    }
    else if (status == SM_ERR_CONDITIONS_NOT_SATISFIED) {
        LOGI(TAG, "Allowing SM_ERR_CONDITIONS_NOT_SATISFIED for CreateCurve");
    }

    status = Kose_API_CheckObjectExists(&keyStore->session->s_ctx, keyObject->keyId, &exists);
    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
        goto exit;
    }
    ENSURE_OR_GO_EXIT(status == SM_OK);

    if (exists == kKOSE_Result_SUCCESS) {
        /* Check if object is of same curve id */
        status = Kose_API_EC_CurveGetId(&keyObject->keyStore->session->s_ctx, keyObject->keyId, &retCurveId);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);

        if (retCurveId == keyObject->curve_id) {
            curveId = kKOSE_ECCurve_NA;
        }
        else {
            LOGI(TAG, "Cannot overwrite object with different curve id");
            goto exit;
        }
    }
    else {
        curveId = keyObject->curve_id;
    }

    if (exists == kKOSE_Result_FAILURE) {
        key_part = kKOSE_KeyPart_Public;
    }

    switch (keyObject->curve_id) {
    default: {
        asn_retval = kss_util_pkcs8_asn1_get_ec_public_key_index(key, keyLen, &publicKeyIndex, &publicKeyLen);
        if (asn_retval != kStatus_KSS_Success) {
            LOGI(TAG, "error in kss_util_pkcs8_asn1_get_ec_public_key_index");
            goto exit;
        }

        asn_retval = getEccPrivPubKeyLen((uint32_t)keyObject->curve_id, &std_pubKey_len, &std_privKey_len);
        if (asn_retval != kStatus_KSS_Success) {
            LOGI(TAG, "error in getEccPrivPubKeyLen");
            goto exit;
        }

        if (publicKeyLen != std_pubKey_len) {
            if (key[publicKeyIndex] == 0) {
                publicKeyIndex++;
                publicKeyLen--;
            }
        }
        if (publicKeyLen != std_pubKey_len) {
            LOGI(TAG, "error in public key length");
            goto exit;
        }
    }
    }

#ifdef TMP_ENDIAN_VERBOSE
    {
        printf("Pub Key Before Reverse:\n");
        for (size_t z = 0; z < publicKeyLen; z++) {
            printf("%02X.", key[publicKeyIndex + z]);
        }
        printf("\n");
    }
#endif

    // Conditionally Reverse Endianness
#if KSS_HAVE_EC_MONT || KSS_HAVE_EC_ED
    if ((keyObject->curve_id == kKOSE_ECCurve_ECC_MONT_DH_25519) ||
        (keyObject->curve_id == kKOSE_ECCurve_ECC_MONT_DH_448) ||
        (keyObject->curve_id == kKOSE_ECCurve_ECC_ED_25519)) {
        size_t i        = 0;
        size_t nByteKey = 32; // Corresponds to kKOSE_ECCurve_ECC_MONT_DH_25519

        if (keyObject->curve_id == kKOSE_ECCurve_ECC_MONT_DH_448) {
            nByteKey = 56;
        }

        while (i < nByteKey) {
            pubKeyReversed[i] = key[publicKeyIndex + publicKeyLen - i - 1];
            i++;
        }
        pPublicKey = &pubKeyReversed[0];
    }
    else
#endif // KSS_HAVE_EC_MONT || KSS_HAVE_EC_ED
    {
        pPublicKey = &key[publicKeyIndex];
    }

#ifdef TMP_ENDIAN_VERBOSE
    {
        printf("Pub Key After Reverse:\n");
        for (size_t z = 0; z < publicKeyLen; z++) {
            printf("%02X.", pPublicKey[z]);
        }
        printf("\n");
    }
#endif

    status = kss_kose_LL_set_ec_key(&keyStore->session->s_ctx,
        &kose_policy,
        KOSE_MaxAttemps_NA,
        keyObject->keyId,
        curveId,
        NULL,
        0,
        pPublicKey,
        publicKeyLen,
        transient_type,
        key_part,
        exists);
    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
        goto exit;
    }
    ENSURE_OR_GO_EXIT(status == SM_OK);

    retval = kStatus_KSS_Success;
exit:
    return retval;
}
#endif //kss_kose_key_store_set_ecc_public_key
/*
static kss_status_t kss_kose_key_store_set_ecc_private_key(kss_kose_key_store_t *keyStore,
    kss_kose_object_t *keyObject,
    const uint8_t *key,
    size_t keyLen,
    size_t keyBitLen,
    void *policy_buff,
    size_t policy_buff_len)
{
    kss_status_t retval     = kStatus_KSS_Fail;
    kss_status_t asn_retval = kStatus_KSS_Fail;
    smStatus_t status       = SM_NOT_OK;
    KosePolicy_t kose_policy;
    KOSE_INS_t transient_type;
    KOSE_ECCurve_t curveId    = keyObject->curve_id;
    KOSE_KeyPart_t key_part   = kKOSE_KeyPart_NA;
    KOSE_Result_t exists      = kKOSE_Result_NA;
    KOSE_ECCurve_t retCurveId = keyObject->curve_id;
    size_t std_pubKey_len      = 0;
    size_t std_privKey_len     = 0;
    const uint8_t *pPrivKey    = NULL;
    size_t privKeyLen          = keyLen;
    uint16_t privateKeyIndex   = 0;

    status = Kose_API_PutKey(&keyStore->session->s_ctx, 0x7788, 0x010203, 0x01, (uint8_t *)"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F", privKeyLen);

    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
        goto exit;
    }
    ENSURE_OR_GO_EXIT(status == SM_OK);

    retval = kStatus_KSS_Success;

exit:
    return retval;
}
*/
static kss_status_t kss_kose_key_store_set_ecc_key(kss_kose_key_store_t *keyStore,
    kss_kose_object_t *keyObject,
    const uint8_t *key,
    size_t keyLen,
    size_t keyBitLen,
    void *policy_buff,
    size_t policy_buff_len)
{
    kss_status_t retval     = kStatus_KSS_Fail;
    smStatus_t status       = SM_NOT_OK;

    status = Kose_API_PutKey(&keyStore->session->s_ctx, keyObject->keyId, keyObject->acl, key, keyLen);

    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
        goto exit;
    }
    ENSURE_OR_GO_EXIT(status == SM_OK);

    retval = kStatus_KSS_Success;

exit:
    return retval;
}

kss_status_t kss_kose_key_store_set_key(kss_kose_key_store_t *keyStore,
    kss_kose_object_t *keyObject,
    const uint8_t *key,
    size_t keyLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen)
{
    kss_status_t retval = kStatus_KSS_Fail;

#if KSSFTR_KOSE_KEY_SET

    kss_cipher_type_t cipher_type = kKSS_CipherType_NONE;
    uint8_t *ppolicySet;
    size_t valid_policy_buff_len                  = 0;
    kss_status_t kssStatus = kStatus_KSS_Fail;

    AX_UNUSED_ARG(optionsLen);

    ENSURE_OR_GO_EXIT(keyStore);
    ENSURE_OR_GO_EXIT(keyObject);

    if (keyBitLen) {
        ENSURE_OR_GO_EXIT(key);
    }
    cipher_type = (kss_cipher_type_t)keyObject->cipherType;
    ppolicySet = NULL;

    LOGD(TAG, "keyBitLen : %zu", keyBitLen);
    ENSURE_OR_GO_EXIT(keyBitLen == 256);

    switch (cipher_type) {
#if KSSFTR_KOSE_ECC
    case kKSS_CipherType_EC_NIST_P:
#if KSS_HAVE_EC_NIST_K
    case kKSS_CipherType_EC_NIST_K:
#endif
#if KSS_HAVE_EC_BP
    case kKSS_CipherType_EC_BRAINPOOL:
#endif
#if KSS_HAVE_EC_MONT
    case kKSS_CipherType_EC_MONTGOMERY:
#endif
#if KSS_HAVE_EC_ED
    case kKSS_CipherType_EC_TWISTED_ED:
#endif
        kssStatus = kss_kose_key_store_set_ecc_key(
            keyStore, keyObject, key, keyLen, keyBitLen, ppolicySet, valid_policy_buff_len);
        if (kssStatus != kStatus_KSS_Success) {
            retval = kssStatus;
            goto exit;
        }
        break;
#endif // KSSFTR_KOSE_ECC
    default:
        goto exit;
    }
    retval = kStatus_KSS_Success;
exit:
#endif /* KSSFTR_KOSE_KEY_SET */
    return retval;
}

#ifdef __cplusplus
}
#endif