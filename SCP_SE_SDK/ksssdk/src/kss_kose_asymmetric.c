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

#include "mbedtls/asn1.h"
#include "mbedtls/bignum.h"

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
#endif //KSSFTR_KOSE_ECC
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
    parse_ecdsa_der_signature_to_rs64(signature, signatureLen, signature_rs);
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