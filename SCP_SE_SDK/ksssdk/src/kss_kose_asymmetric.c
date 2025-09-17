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

#include "kss_kose_asymmetric.h"
#include "kona_kss_kose_types.h"
#include "kose_APDU_impl.h"
#include "kona_kss_ftr_default.h"
#include "kona_kss_util_rsa_sign_utils.h"

#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/asn1.h"
#include "mbedtls/bignum.h"
#endif

static const char *TAG = "kss_kose_asymmetric.c";

static KOSE_ECSignatureAlgo_t kose_get_ec_sign_hash_mode(kss_algorithm_t algorithm)
{
    KOSE_ECSignatureAlgo_t mode;
    switch (algorithm) {
    case kAlgorithm_KSS_SHA1:
    case kAlgorithm_KSS_ECDSA_SHA1:
        mode = kKOSE_ECSignatureAlgo_SHA;
        break;
    case kAlgorithm_KSS_SHA224:
    case kAlgorithm_KSS_ECDSA_SHA224:
        mode = kKOSE_ECSignatureAlgo_SHA_224;
        break;
    case kAlgorithm_KSS_SHA256:
    case kAlgorithm_KSS_ECDSA_SHA256:
        mode = kKOSE_ECSignatureAlgo_SHA_256;
        break;
    case kAlgorithm_KSS_SHA384:
    case kAlgorithm_KSS_ECDSA_SHA384:
        mode = kKOSE_ECSignatureAlgo_SHA_384;
        break;
    case kAlgorithm_KSS_SHA512:
    case kAlgorithm_KSS_ECDSA_SHA512:
        mode = kKOSE_ECSignatureAlgo_SHA_512;
        break;
    default:
        mode = kKOSE_ECSignatureAlgo_PLAIN;
        break;
    }
    return mode;
}

#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
static int parse_ecdsa_der_signature_to_rs64(const unsigned char *der_sig, size_t der_sig_len,
                                      unsigned char *rs64)
{
    int ret;
    mbedtls_asn1_buf seq;
    mbedtls_mpi R, S;
    mbedtls_mpi_init(&R);
    mbedtls_mpi_init(&S);

    unsigned char *p = (unsigned char *)der_sig;
    const unsigned char *end = der_sig + der_sig_len;

    ret = mbedtls_asn1_get_tag(&p, end, &seq.len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) goto cleanup;

    end = p + seq.len;

    // Get R
    ret = mbedtls_asn1_get_mpi(&p, end, &R);
    if (ret != 0) goto cleanup;

    // Get S
    ret = mbedtls_asn1_get_mpi(&p, end, &S);
    if (ret != 0) goto cleanup;

    // r || s 64바이트로 합치기
    memset(rs64, 0, 64);
    ret = mbedtls_mpi_write_binary(&R, rs64, 32);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_write_binary(&S, rs64 + 32, 32);
    if (ret != 0) goto cleanup;

cleanup:
    mbedtls_mpi_free(&R);
    mbedtls_mpi_free(&S);
    return ret;
}
#endif

/* ************************************************************************** */
/* Functions : kss_kose_asym                                                 */
/* ************************************************************************** */

kss_status_t kss_kose_asymmetric_context_init(kss_kose_asymmetric_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode)
{
    LOGD(TAG, "kss_kose_asymmetric_context_init");

    kss_status_t retval = kStatus_KSS_Success;
    if (context == NULL) {
        return kStatus_KSS_Fail;
    }
    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;

    return retval;
}

kss_status_t kss_kose_asymmetric_sign_digest(
    kss_kose_asymmetric_t *context, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
    smStatus_t status   = SM_NOT_OK;
    KOSE_ECSignatureAlgo_t ecSignAlgo = kKOSE_ECSignatureAlgo_NA;

    LOGD(TAG, "kss_kose_asymmetric_sign_digest");

    switch (context->keyObject->cipherType) {
#if KSSFTR_KOSE_ECC
    case kKSS_CipherType_EC_NIST_P:
#if KSS_HAVE_EC_NIST_K
    case kKSS_CipherType_EC_NIST_K:
#endif
#if KSS_HAVE_EC_BP
    case kKSS_CipherType_EC_BRAINPOOL:
#endif
    {
        ecSignAlgo = kose_get_ec_sign_hash_mode(context->algorithm);
        status     = Kose_API_ECDSASign(&context->session->s_ctx,
            context->keyObject->keyId,
            ecSignAlgo,
            digest,
            digestLen,
            signature,
            signatureLen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
        }
    } break;
#endif // KSSFTR_KOSE_ECC
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA && !KSS_HAVE_HOSTCRYPTO_NONE
    case kKSS_CipherType_RSA:
    case kKSS_CipherType_RSA_CRT: {
#if 0 // kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1 Start 삭제 예정
        if ((context->algorithm <= kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA512) &&
            (context->algorithm >= kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA1)) {
            /* Perform EMSA encoding on input data and and RSA decrypt on emsa data --> RSA sign without hash */
            /* clang-format off */
            uint8_t emsa_data[512] = {0,}; /* MAX - SHA512*/
            size_t emsa_len = sizeof(emsa_data);
            uint8_t encode_ret = 0;
            /* clang-format on */

            encode_ret = emsa_encode(context, digest, digestLen, emsa_data, &emsa_len);
            if (0 != encode_ret) {
                if (encode_ret == 2) {
                    return kStatus_KSS_ApduThroughputError;
                }
                else {
                    return kStatus_KSS_Fail;
                }
            }
            status = Kose_API_RSADecrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kKOSE_RSAEncryptionAlgo_NO_PAD,
                emsa_data,
                emsa_len,
                signature,
                signatureLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
            }
        }
#endif // kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1 End
#if 0 // kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512 Start 구현 예정
        if ((context->algorithm <= kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512) &&
                 (context->algorithm >= kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA1)) {
            uint8_t encode_ret = 0;
            /* Perform PKCS1-v15 encoding on input data and and RSA decrypt on PKCS1-v15 data --> RSA sign without hash */
            /* clang-format off */
            uint8_t pkcs1v15_encode_data[512] = {0,}; /* MAX - SHA512*/
            size_t encode_data_len = sizeof(pkcs1v15_encode_data);
            
            /* clang-format on */
            encode_ret = pkcs1_v15_encode(context, digest, digestLen, pkcs1v15_encode_data, &encode_data_len);
            if (0 != encode_ret) {
                if (encode_ret == 2) {
                    return kStatus_KSS_ApduThroughputError;
                }
                else {
                    return kStatus_KSS_Fail;
                }
            }
           
            status = Kose_API_RSASign(&context->session->s_ctx,
                context->keyObject->keyId,
                kKOSE_RSAEncryptionAlgo_NO_PAD,
                pkcs1v15_encode_data,
                encode_data_len,
                signature,
                signatureLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
            }
        }
#endif // kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512 End
#if 0 // kAlgorithm_KSS_RSASSA_PKCS1_V1_5_NO_HASH / kAlgorithm_KSS_RSASSA_NO_PADDING Start 삭제 예정
        else if (context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_V1_5_NO_HASH) {
            uint8_t encode_ret = 0;
            /* Perform PKCS1-v15 encoding on input data and and RSA decrypt on PKCS1-v15 data --> RSA sign without hash */
            /* clang-format off */
            uint8_t pkcs1v15_encode_data[512] = {0,}; /* MAX - SHA512*/
            size_t encode_data_len = sizeof(pkcs1v15_encode_data);
            /* clang-format on */

            encode_ret = pkcs1_v15_encode_no_hash(context, digest, digestLen, pkcs1v15_encode_data, &encode_data_len);
            if (0 != encode_ret) {
                if (encode_ret == 2) {
                    return kStatus_KSS_ApduThroughputError;
                }
                else {
                    return kStatus_KSS_Fail;
                }
            }
            status = Kose_API_RSADecrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kKOSE_RSAEncryptionAlgo_NO_PAD,
                pkcs1v15_encode_data,
                encode_data_len,
                signature,
                signatureLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
            }
        }

        else if (context->algorithm == kAlgorithm_KSS_RSASSA_NO_PADDING) {
            uint8_t padded_data[512] = {0};
            size_t padded_len        = sizeof(padded_data);

            size_t parsedKeyByteLen      = 0;
            uint16_t u16parsedKeyByteLen = 0;
            status = Kose_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &u16parsedKeyByteLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                return kStatus_KSS_ApduThroughputError;
            }
            parsedKeyByteLen = u16parsedKeyByteLen;
            if (status != SM_OK) {
                return kStatus_KSS_Fail;
            }

            if (digestLen <= parsedKeyByteLen && digestLen > 0) {
                memset(padded_data, 0x00, padded_len);
                memcpy(&padded_data[parsedKeyByteLen - digestLen], &digest[0], digestLen);
                padded_len = parsedKeyByteLen;
            }
            else {
                return kStatus_KSS_Fail;
            }
            status = Kose_API_RSADecrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kKOSE_RSAEncryptionAlgo_NO_PAD,
                padded_data,
                padded_len,
                signature,
                signatureLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
            }
        }
#endif // kAlgorithm_KSS_RSASSA_PKCS1_V1_5_NO_HASH / kAlgorithm_KSS_RSASSA_NO_PADDING End
/*
        else {
            LOGE(TAG, "Selected padding is not supported for RSA Sign in KOSE");
            return kStatus_KSS_Fail;
        }
*/
    } break;
#endif  // KSSFTR_KOSE_RSA
    default:
        break;
    }
    if (status == SM_OK) {
        retval = kStatus_KSS_Success;
    }

    return retval;
}

kss_status_t kss_kose_asymmetric_verify_digest(kss_kose_asymmetric_t *context,
    const uint8_t *digest,
    size_t digestLen,
    const uint8_t *signature,
    size_t signatureLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
    smStatus_t status     = SM_NOT_OK;
    KOSE_Result_t result = kKOSE_Result_FAILURE;
    uint8_t signature_rs[64] ;
    

#if KSSFTR_KOSE_ECC
#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
    parse_ecdsa_der_signature_to_rs64(signature, signatureLen, signature_rs);
#else
    ecdsa_der_to_rs64(signature, signatureLen, signature_rs);
#endif
    switch (context->keyObject->cipherType) {
#if KSSFTR_KOSE_ECC
    case kKSS_CipherType_EC_NIST_P:
#if KSS_HAVE_EC_NIST_K
    case kKSS_CipherType_EC_NIST_K:
#endif
#if KSS_HAVE_EC_BP
    case kKSS_CipherType_EC_BRAINPOOL:
#endif
    {
        KOSE_ECSignatureAlgo_t ecSignAlgo = kose_get_ec_sign_hash_mode(context->algorithm);
        status                            = Kose_API_ECDSAVerify(&context->session->s_ctx,
            context->keyObject->keyId,
            ecSignAlgo,
            digest,
            digestLen,
            signature_rs,
            64,
            &result);
    } break;

#endif // KSSFTR_KOSE_ECC
    default:
        break;
    }
#endif // KSSFTR_KOSE_ECC || KSSFTR_KOSE_RSA

#if KSSFTR_KOSE_ECC || KSSFTR_KOSE_RSA
    if (status == SM_OK) {
        if (result == kKOSE_Result_SUCCESS) {
            retval = kStatus_KSS_Success;
        }
    }
    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
    }
#endif // KSSFTR_KOSE_ECC || KSSFTR_KOSE_RSA

    return retval;
}

void kss_kose_asymmetric_context_free(kss_kose_asymmetric_t *context)
{
    memset(context, 0, sizeof(*context));
}

kss_status_t kss_kose_asymmetric_encrypt(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    return kStatus_KSS_Success;
}

kss_status_t kss_kose_asymmetric_decrypt(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    return kStatus_KSS_Success;
}

#ifdef __cplusplus
}
#endif