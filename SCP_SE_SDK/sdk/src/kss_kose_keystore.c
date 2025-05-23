/** @file */
#ifdef __cplusplus
extern "C" {
#endif

#include "kona_kss_api.h"
#include "kona_kss_kose_types.h"
#include "kona_kss_ftr_default.h"
#include "kose_APDU_impl.h"
#include "kss_kose_keystore.h"
#include "ensure.h"
#include "kona_kss_util_asn1_der.h"
#include "debug.h"

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
    LOGD(TAG, "kss_kose_key_store_context_init start");
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

kss_status_t kss_kose_key_store_get_key(
    kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject, uint8_t *key, size_t *keylen, size_t *pKeyBitLen)
{
    kss_status_t retval           = kStatus_KSS_Fail;
    kss_cipher_type_t cipher_type = kKSS_CipherType_NONE;
    smStatus_t status             = SM_NOT_OK;
    uint16_t size                 = 0;
    ENSURE_OR_GO_EXIT(keyObject);
    ENSURE_OR_GO_EXIT(key);
    ENSURE_OR_GO_EXIT(keylen);
    ENSURE_OR_GO_EXIT(pKeyBitLen);

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
        uint8_t *key_buf  = NULL;
        size_t key_buflen = 0;

        /* Return the Key length including the ECC DER Header */
        add_ecc_header(key, keylen, &key_buf, &key_buflen, keyObject->curve_id);
        ENSURE_OR_GO_EXIT(*keylen > key_buflen);
        (*keylen) = (*keylen) - key_buflen;

        //status = Kose_API_ReadObject(&keyStore->session->s_ctx, keyObject->keyId, 0, 0, key_buf, keylen);
        status = Kose_API_GetData(&keyStore->session->s_ctx, keyObject->keyId, key_buf, keylen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);

        /* Change Endiannes. */
#if KSS_HAVE_EC_MONT || KSS_HAVE_EC_ED
        if ((keyObject->curve_id == kKOSE_ECCurve_ECC_MONT_DH_25519) ||
            (keyObject->curve_id == kKOSE_ECCurve_ECC_MONT_DH_448) ||
            (keyObject->curve_id == kKOSE_ECCurve_ECC_ED_25519)) {
            for (size_t keyValueIdx = 0; keyValueIdx < (*keylen >> 1); keyValueIdx++) {
                uint8_t swapByte                   = key_buf[keyValueIdx];
                key_buf[keyValueIdx]               = key_buf[*keylen - 1 - keyValueIdx];
                key_buf[*keylen - 1 - keyValueIdx] = swapByte;
            }
        }
#endif

        /* Return the Key length with header length */
        *keylen += key_buflen;

        break;
    }
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA
    case kKSS_CipherType_RSA:
    case kKSS_CipherType_RSA_CRT: {
        uint8_t modulus[1024] = {0};
        uint8_t exponent[4]   = {0};
        size_t modLen         = sizeof(modulus);
        size_t expLen         = sizeof(exponent);

        status = Kose_API_ReadRSA(
            &keyStore->session->s_ctx, keyObject->keyId, 0, 0, kKOSE_RSAPubKeyComp_MOD, modulus, &modLen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);

        status = Kose_API_ReadRSA(
            &keyStore->session->s_ctx, keyObject->keyId, 0, 0, kKOSE_RSAPubKeyComp_PUB_EXP, exponent, &expLen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);

        if (kss_util_asn1_rsa_get_public(key, keylen, modulus, modLen, exponent, expLen) != kStatus_KSS_Success) {
            goto exit;
        }
    } break;
#endif // KSSFTR_KOSE_RSA && && KSS_HAVE_RSA
#if 0 //tag 1
    case kKSS_CipherType_AES:
        //status = Kose_API_ReadObject(&keyStore->session->s_ctx, keyObject->keyId, 0, 0, key, keylen);
        status = Kose_API_GetData(&keyStore->session->s_ctx, keyObject->keyId);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);
        break;
    case kKSS_CipherType_Binary:
    case kKSS_CipherType_Certificate: {
        uint16_t rem_data = 0;
        uint16_t offset   = 0;
        size_t max_buffer = 0;
        status            = Kose_API_ReadSize(&keyStore->session->s_ctx, keyObject->keyId, &size);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);
        if (*keylen < size) {
            LOGE(TAG, "Insufficient buffer ");
            goto exit;
        }

        rem_data = size;
        *keylen  = size;
        while (rem_data > 0) {
            uint16_t chunk = (rem_data > BINARY_WRITE_MAX_LEN) ? BINARY_WRITE_MAX_LEN : rem_data;
            rem_data       = rem_data - chunk;
            max_buffer     = chunk;
            status         = Kose_API_ReadObject(
                &keyStore->session->s_ctx, keyObject->keyId, offset, chunk, (key + offset), &max_buffer);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
                goto exit;
            }
            ENSURE_OR_GO_EXIT(status == SM_OK);
            offset = offset + chunk;
        }
        if (cipher_type == kKSS_CipherType_Certificate) { /*ASN1 Parse step to remove extra padded 0*/
            int ret         = 0;
            size_t taglen   = 0;
            size_t bufIndex = 0;
            ret             = asn_1_parse_tlv(key, &taglen, &bufIndex);
            if (ret != 0) {
                goto exit;
            }
            taglen += bufIndex;

            ENSURE_OR_GO_EXIT(taglen <= (*keylen));
            if ((taglen == ((*keylen) - 1)) && (key[taglen] == 0)) {
                (*keylen)--;
            }
        }
    } break;
    case kKSS_CipherType_DES:
        status = Kose_API_ReadObject(&keyStore->session->s_ctx, keyObject->keyId, 0, 0, key, keylen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);
        break;
    case kKSS_CipherType_PCR:
        status = Kose_API_ReadObject(&keyStore->session->s_ctx, keyObject->keyId, 0, 0, key, keylen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);
        break;
    case kKSS_CipherType_Count:
        status = Kose_API_ReadObject(&keyStore->session->s_ctx, keyObject->keyId, 0, 0, key, keylen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);
        break;
#endif //tag 1
    default:
        goto exit;
    }

    retval = kStatus_KSS_Success;
exit:
    return retval;
}

#ifdef __cplusplus
}
#endif