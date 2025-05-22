//#include "kss_kose_session.h"
#include <mbedtls/md.h>

#include "kss_kose_asymmetric.h"
#include "kona_kss_kose_types.h"
#include "kose_APDU_impl.h"
#include "kona_kss_mbedtls_types.h"
#include "kss_kose_mbedtls.h"

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

/* ************************************************************************** */
/* Functions : kss_kose_asym                                                 */
/* ************************************************************************** */

kss_status_t kss_kose_asymmetric_context_init(kss_kose_asymmetric_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode)
{
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
/*
#if KSSFTR_KOSE_ECC || KSSFTR_KOSE_RSA
    if (kStatus_KSS_Success != kose_check_input_len(digestLen, context->algorithm)) {
        LOG_E("Algorithm and digest length do not match");
        return kStatus_KSS_Fail;
    }
#endif
*/
    switch (context->keyObject->cipherType) {
#if KSSFTR_KOSE_ECC
    case kKSS_CipherType_EC_NIST_P:
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
#if KSS_HAVE_KOSE_VER_GTE_07_02 && KSS_HAVE_EC_MONT
    case kKSS_CipherType_EC_MONTGOMERY: {
        LOG_W(
            "Sign operation is not supported for "
            "kKSS_CipherType_EC_MONTGOMERY curve");
        return kStatus_KSS_Fail;
    } break;
#endif // KSS_HAVE_KOSE_VER_GTE_07_02 && KSS_HAVE_EC_MONT
#endif //KSSFTR_KOSE_ECC
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA && !KSS_HAVE_HOSTCRYPTO_NONE
    case kKSS_CipherType_RSA:
    case kKSS_CipherType_RSA_CRT: {
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
                kSE05x_RSAEncryptionAlgo_NO_PAD,
                emsa_data,
                emsa_len,
                signature,
                signatureLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
            }
        }
        else if ((context->algorithm <= kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512) &&
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
            status = Kose_API_RSADecrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kSE05x_RSAEncryptionAlgo_NO_PAD,
                pkcs1v15_encode_data,
                encode_data_len,
                signature,
                signatureLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
            }
        }
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
                kSE05x_RSAEncryptionAlgo_NO_PAD,
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
                kSE05x_RSAEncryptionAlgo_NO_PAD,
                padded_data,
                padded_len,
                signature,
                signatureLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
            }
        }
        else {
            LOG_E("Selected padding is not supported for RSA Sign in SE050");
            return kStatus_KSS_Fail;
        }
    } break;
#endif // KSSFTR_KOSE_RSA && KSS_HAVE_RSA && !KSS_HAVE_HOSTCRYPTO_NONE
    default:
        break;
    }
    if (status == SM_OK) {
        retval = kStatus_KSS_Success;
    }

    return retval;
}

#if 0
kss_status_t kss_kose_asymmetric_encrypt(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA
    smStatus_t status                           = SM_NOT_OK;
    KOSE_RSAEncryptionAlgo_t rsaEncryptionAlgo = kose_get_rsa_encrypt_mode(context->algorithm);
    if (context->keyObject == NULL) {
        return kStatus_KSS_Fail;
    }
    status                                      = Kose_API_RSAEncrypt(
        &context->session->s_ctx, context->keyObject->keyId, rsaEncryptionAlgo, srcData, srcLen, destData, destLen);
    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
    }
    else if (status == SM_OK) {
        retval = kStatus_KSS_Success;
    }
#else
    AX_UNUSED_ARG(context);
    AX_UNUSED_ARG(srcData);
    AX_UNUSED_ARG(srcLen);
    AX_UNUSED_ARG(destData);
    AX_UNUSED_ARG(destLen);
#endif
    return retval;
}

kss_status_t kss_kose_asymmetric_decrypt(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA
    smStatus_t status = SM_NOT_OK;

    KOSE_RSAEncryptionAlgo_t rsaEncryptionAlgo = kose_get_rsa_encrypt_mode(context->algorithm);
    if (context->keyObject == NULL) {
        return retval;
    }
    status                                      = Kose_API_RSADecrypt(
        &context->session->s_ctx, context->keyObject->keyId, rsaEncryptionAlgo, srcData, srcLen, destData, destLen);
    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
    }
    else if (status == SM_OK) {
        retval = kStatus_KSS_Success;
    }
#else
    AX_UNUSED_ARG(context);
    AX_UNUSED_ARG(srcData);
    AX_UNUSED_ARG(srcLen);
    AX_UNUSED_ARG(destData);
    AX_UNUSED_ARG(destLen);
#endif
    return retval;
}


#if 0
kss_status_t kss_kose_asymmetric_sign_digest(
    kss_kose_asymmetric_t *context, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
    smStatus_t status   = SM_NOT_OK;

#if KSSFTR_KOSE_ECC
    KOSE_ECSignatureAlgo_t ecSignAlgo = kKOSE_ECSignatureAlgo_NA;
#endif

#if KSSFTR_KOSE_ECC || KSSFTR_KOSE_RSA
    if (kStatus_KSS_Success != kose_check_input_len(digestLen, context->algorithm)) {
        LOG_E("Algorithm and digest length do not match");
        return kStatus_KSS_Fail;
    }
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
#if KSS_HAVE_KOSE_VER_GTE_07_02 && KSS_HAVE_EC_MONT
    case kKSS_CipherType_EC_MONTGOMERY: {
        LOG_W(
            "Sign operation is not supported for "
            "kKSS_CipherType_EC_MONTGOMERY curve");
        return kStatus_KSS_Fail;
    } break;
#endif // KSS_HAVE_KOSE_VER_GTE_07_02 && KSS_HAVE_EC_MONT
#endif //KSSFTR_KOSE_ECC
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA && !KSS_HAVE_HOSTCRYPTO_NONE
    case kKSS_CipherType_RSA:
    case kKSS_CipherType_RSA_CRT: {
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
        else if ((context->algorithm <= kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512) &&
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
        else {
            LOG_E("Selected padding is not supported for RSA Sign in SE050");
            return kStatus_KSS_Fail;
        }
    } break;
#endif // KSSFTR_KOSE_RSA && KSS_HAVE_RSA && !KSS_HAVE_HOSTCRYPTO_NONE
    default:
        break;
    }

    if (status == SM_OK) {
        retval = kStatus_KSS_Success;
    }

    return retval;
}
#endif




kss_status_t kss_kose_asymmetric_sign(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if (KSSFTR_KOSE_RSA && KSS_HAVE_RSA) || (KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED)
    smStatus_t status = SM_NOT_OK;
#endif
#if KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED
    size_t offset = 0;
#endif

    switch (context->keyObject->cipherType) {
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA
    case kKSS_CipherType_RSA:
    case kKSS_CipherType_RSA_CRT: {
        KOSE_RSASignatureAlgo_t rsaSigningAlgo = kose_get_rsa_sign_hash_mode(context->algorithm);
        uint16_t key_size_bytes                 = 0;

        if (context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512 ||
            context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA512) {
            status = Kose_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &key_size_bytes);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                return kStatus_KSS_ApduThroughputError;
            }
            if (status != SM_OK) {
                return kStatus_KSS_Fail;
            }

            if ((key_size_bytes * 8) == 512) {
                return kStatus_KSS_Fail;
            }
        }

        status = Kose_API_RSASign(
            &context->session->s_ctx, context->keyObject->keyId, rsaSigningAlgo, srcData, srcLen, destData, destLen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
        }
    } break;
#endif // KSSFTR_KOSE_RSA && KSS_HAVE_RSA
#if KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED
    case kKSS_CipherType_EC_TWISTED_ED: {
        if (context->algorithm == kAlgorithm_KSS_SHA512) {
            KOSE_EDSignatureAlgo_t ecSignAlgo = kKOSE_EDSignatureAlgo_ED25519PURE_SHA_512;
            status                             = Kose_API_EdDSASign(
                &context->session->s_ctx, context->keyObject->keyId, ecSignAlgo, srcData, srcLen, destData, destLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
            }
        }

#ifdef TMP_ENDIAN_VERBOSE_SIGN
        {
            printf("Signature before Reverse:\n");
            for (size_t z = 0; z < *destLen; z++) {
                printf("%02X.", destData[z]);
            }
            printf("\n");
        }
#endif

        // Revert Endianness
        offset = 0;

        for (size_t keyValueIdx = 0; keyValueIdx < (*destLen >> 2); keyValueIdx++) {
            uint8_t swapByte               = destData[keyValueIdx];
            destData[offset + keyValueIdx] = destData[offset + (*destLen >> 1) - 1 - keyValueIdx];
            if (offset + (*destLen >> 1) - 1 - keyValueIdx < *destLen) {
                destData[offset + (*destLen >> 1) - 1 - keyValueIdx] = swapByte;
            }
            else {
                return kStatus_KSS_Fail;
            }
        }

        offset = *destLen >> 1;

        for (size_t keyValueIdx = 0; keyValueIdx < (*destLen >> 2); keyValueIdx++) {
            uint8_t swapByte = destData[offset + keyValueIdx];
            if ((UINT_MAX - offset) < keyValueIdx) {
                return kStatus_KSS_Fail;
            }
            destData[offset + keyValueIdx]                       = destData[offset + (*destLen >> 1) - 1 - keyValueIdx];
            destData[offset + (*destLen >> 1) - 1 - keyValueIdx] = swapByte;
        }

#ifdef TMP_ENDIAN_VERBOSE_SIGN
        {
            printf("Signature after Reverse:\n");
            for (size_t z = 0; z < *destLen; z++) {
                printf("%02X.", destData[z]);
            }
            printf("\n");
        }
#endif

    } break;
#endif // KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED
    default:
        break;
    }

#if (KSSFTR_KOSE_RSA && KSS_HAVE_RSA) || (KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED)
    // status is set only in case of RSA or ED.
    if (status == SM_OK) {
        retval = kStatus_KSS_Success;
    }
#endif

    return retval;
}

kss_status_t kss_kose_asymmetric_verify_digest(kss_kose_asymmetric_t *context,
    const uint8_t *digest,
    size_t digestLen,
    const uint8_t *signature,
    size_t signatureLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_KOSE_ECC || KSSFTR_KOSE_RSA
    smStatus_t status     = SM_NOT_OK;
    KOSE_Result_t result = kKOSE_Result_FAILURE;
#endif // KSSFTR_KOSE_ECC || KSSFTR_KOSE_RSA

#if KSSFTR_KOSE_ECC || KSSFTR_KOSE_RSA
    if (kStatus_KSS_Success != kose_check_input_len(digestLen, context->algorithm)) {
        LOG_E("Algorithm and digest length do not match");
        return kStatus_KSS_Fail;
    }

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
        status                             = Kose_API_ECDSAVerify(&context->session->s_ctx,
            context->keyObject->keyId,
            ecSignAlgo,
            digest,
            digestLen,
            signature,
            signatureLen,
            &result);
    } break;
#if KSS_HAVE_KOSE_VER_GTE_07_02 && KSS_HAVE_EC_MONT
    case kKSS_CipherType_EC_MONTGOMERY: {
        LOG_W(
            "Verify operation is not supported for "
            "kKSS_CipherType_EC_MONTGOMERY curve");
        return kStatus_KSS_Fail;
    } break;
#endif // KSS_HAVE_KOSE_VER_GTE_07_02 && KSS_HAVE_EC_MONT
#endif // KSSFTR_KOSE_ECC
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA && !KSS_HAVE_HOSTCRYPTO_NONE
    case kKSS_CipherType_RSA:
    case kKSS_CipherType_RSA_CRT: {
        if ((context->algorithm <= kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA512) &&
            (context->algorithm >= kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA1)) {
            /* clang-format off */
            uint8_t dec_data[512] = { 0, }; /* MAX - SHA512*/
            size_t dec_len = sizeof(dec_data);
            /* clang-format on */

            status = Kose_API_RSAEncrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kKOSE_RSAEncryptionAlgo_NO_PAD,
                signature,
                signatureLen,
                dec_data,
                &dec_len);
            if (status == SM_OK) {
                if (0 == emsa_decode_and_compare(context, dec_data, dec_len, digest, digestLen)) {
                    result = kKOSE_Result_SUCCESS;
                }
            }
        }
        else if ((context->algorithm <= kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512) &&
                 (context->algorithm >= kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA1)) {
            /* clang-format off */
            uint8_t dec_data[512] = { 0, }; /* MAX - SHA512*/
            size_t dec_len = sizeof(dec_data);
            uint8_t pkcs1v15_encode_data[512] = { 0, }; /* MAX - SHA512*/
            size_t encode_data_len = sizeof(pkcs1v15_encode_data);
            /* clang-format on */

            status = Kose_API_RSAEncrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kKOSE_RSAEncryptionAlgo_NO_PAD,
                signature,
                signatureLen,
                dec_data,
                &dec_len);
            if (status == SM_OK) {
                uint8_t encode_ret = 0;
                encode_ret = pkcs1_v15_encode(context, digest, digestLen, pkcs1v15_encode_data, &encode_data_len);
                if (0 != encode_ret) {
                    if (encode_ret == 2) {
                        return kStatus_KSS_ApduThroughputError;
                    }
                    else {
                        return kStatus_KSS_Fail;
                    }
                }

                if (memcmp(dec_data, pkcs1v15_encode_data, encode_data_len) == 0) {
                    result = kKOSE_Result_SUCCESS;
                }
            }
        }
        else if (context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_V1_5_NO_HASH) {
            /* clang-format off */
            uint8_t dec_data[512] = { 0, }; /* MAX - SHA512*/
            size_t dec_len = sizeof(dec_data);
            uint8_t pkcs1v15_encode_data[512] = { 0, }; /* MAX - SHA512*/
            size_t encode_data_len = sizeof(pkcs1v15_encode_data);
            /* clang-format on */

            status = Kose_API_RSAEncrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kKOSE_RSAEncryptionAlgo_NO_PAD,
                signature,
                signatureLen,
                dec_data,
                &dec_len);
            if (status == SM_OK) {
                uint8_t encode_ret = 0;
                encode_ret =
                    pkcs1_v15_encode_no_hash(context, digest, digestLen, pkcs1v15_encode_data, &encode_data_len);
                if (0 != encode_ret) {
                    if (encode_ret == 2) {
                        return kStatus_KSS_ApduThroughputError;
                    }
                    else {
                        return kStatus_KSS_Fail;
                    }
                }

                if (memcmp(dec_data, pkcs1v15_encode_data, encode_data_len) == 0) {
                    result = kKOSE_Result_SUCCESS;
                }
            }
        }
        else if (context->algorithm == kAlgorithm_KSS_RSASSA_NO_PADDING) {
            uint8_t dec_data[512] = {
                0,
            }; /*MAX - RSA4096*/
            uint8_t padded_data[512]     = {0};
            size_t dec_len               = sizeof(dec_data);
            size_t padded_len            = sizeof(padded_data);
            size_t parsedKeyByteLen      = 0;
            uint16_t u16parsedKeyByteLen = 0;

            status = Kose_API_RSAEncrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kKOSE_RSAEncryptionAlgo_NO_PAD,
                signature,
                signatureLen,
                dec_data,
                &dec_len);
            if (status == SM_OK) {
                status = Kose_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &u16parsedKeyByteLen);
                if (status == SM_OK) {
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

                    if (memcmp(&dec_data[0], &padded_data[0], padded_len) == 0) {
                        result = kKOSE_Result_SUCCESS;
                    }
                }
            }
        }
        else {
            LOG_E("Selected padding is not supported for RSA Sign in SE050");
            return kStatus_KSS_Fail;
        }

    } break;
#endif // KSSFTR_KOSE_RSA && KSS_HAVE_RSA && !KSS_HAVE_HOSTCRYPTO_NONE
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

kss_status_t kss_kose_asymmetric_verify(kss_kose_asymmetric_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    const uint8_t *signature,
    size_t signatureLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if (KSSFTR_KOSE_RSA && KSS_HAVE_RSA) || (KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED)
    smStatus_t status     = SM_NOT_OK;
    KOSE_Result_t result = kKOSE_Result_FAILURE;
#endif

    switch (context->keyObject->cipherType) {
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA
    case kKSS_CipherType_RSA:
    case kKSS_CipherType_RSA_CRT: {
        KOSE_RSASignatureAlgo_t rsaSigningAlgo = kose_get_rsa_sign_hash_mode(context->algorithm);
        uint16_t key_size_bytes                 = 0;

        if (context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512 ||
            context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA512) {
            status = Kose_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &key_size_bytes);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                return kStatus_KSS_ApduThroughputError;
            }
            if (status != SM_OK) {
                return kStatus_KSS_Fail;
            }

            if ((key_size_bytes * 8) == 512) {
                return kStatus_KSS_Fail;
            }
        }

        status = Kose_API_RSAVerify(&context->session->s_ctx,
            context->keyObject->keyId,
            rsaSigningAlgo,
            srcData,
            srcLen,
            signature,
            signatureLen,
            &result);
    } break;
#endif // KSSFTR_KOSE_RSA && KSS_HAVE_RSA
#if KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED
    case kKSS_CipherType_EC_TWISTED_ED: {
#ifdef TMP_ENDIAN_VERBOSE
        {
            printf("Signature before Reverse:\n");
            for (size_t z = 0; z < signatureLen; z++) {
                printf("%02X.", signature[z]);
            }
            printf("\n");
        }
#endif

        // Revert Endianness
        uint8_t signature_temp[64] = {0};
        size_t offset              = 0;

        if (signatureLen <= sizeof(signature_temp)) {
            memcpy(signature_temp, &signature[0], signatureLen);
        }
        else {
            return kStatus_KSS_Fail;
        }

        for (size_t keyValueIdx = 0; keyValueIdx < (signatureLen >> 2); keyValueIdx++) {
            uint8_t swapByte = signature_temp[keyValueIdx];
            if (offset + (signatureLen >> 1) - 1 - keyValueIdx < signatureLen) {
                signature_temp[offset + keyValueIdx] = signature_temp[offset + (signatureLen >> 1) - 1 - keyValueIdx];
                signature_temp[offset + (signatureLen >> 1) - 1 - keyValueIdx] = swapByte;
            }
            else {
                return kStatus_KSS_Fail;
            }
        }

        offset = signatureLen >> 1;

        for (size_t keyValueIdx = 0; keyValueIdx < (signatureLen >> 2); keyValueIdx++) {
            uint8_t swapByte = signature_temp[offset + keyValueIdx];
            if ((UINT_MAX - offset) < keyValueIdx) {
                return kStatus_KSS_Fail;
            }
            signature_temp[offset + keyValueIdx] = signature_temp[offset + (signatureLen >> 1) - 1 - keyValueIdx];
            if (offset + (signatureLen >> 1) - 1 - keyValueIdx < signatureLen) {
                signature_temp[offset + (signatureLen >> 1) - 1 - keyValueIdx] = swapByte;
            }
            else {
                return kStatus_KSS_Fail;
            }
        }

#ifdef TMP_ENDIAN_VERBOSE
        {
            printf("Signature after Reverse:\n");
            for (size_t z = 0; z < signatureLen; z++) {
                printf("%02X.", signature_temp[z]);
            }
            printf("\n");
        }
#endif

        if (context->algorithm == kAlgorithm_KSS_SHA512) {
            KOSE_EDSignatureAlgo_t ecSignAlgo = kKOSE_EDSignatureAlgo_ED25519PURE_SHA_512;
            status                             = Kose_API_EdDSAVerify(&context->session->s_ctx,
                context->keyObject->keyId,
                ecSignAlgo,
                srcData,
                srcLen,
                signature_temp,
                signatureLen,
                &result);
        }
    } break;
#endif // KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED
    default:
        break;
    }

#if ((KSSFTR_KOSE_RSA && KSS_HAVE_RSA) || (KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED))
    // status is set only in case of RSA or ED.
    if (status == SM_OK) {
        if (result == kKOSE_Result_SUCCESS) {
            retval = kStatus_KSS_Success;
        }
    }
    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
    }
#endif

    return retval;
}

#endif

void kss_kose_asymmetric_context_free(kss_kose_asymmetric_t *context)
{
    memset(context, 0, sizeof(*context));
}

