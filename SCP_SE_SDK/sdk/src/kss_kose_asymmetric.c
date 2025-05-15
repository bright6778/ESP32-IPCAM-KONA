#include "kss_kose_session.h"
#include "kss_kose_asymmetric.h"
#include "kona_kss_kose_types.h"
#include "kose_APDU_impl.h"

static const char *TAG = "kss_kose_asymmetric.c";

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
    uint8_t rcvbuf[KOSE_MAX_BUF_SIZE_CMD];
    pKoseSession_t koseSession;

    // KOSE Select
    size_t rcvlen;
    koseSession = &context->session->s_ctx;
    if(koseSession->fp_TXn(koseSession, (uint8_t *)"\x00\xa4\x04\x00\x01\x0a", 6, rcvbuf, &rcvlen) != SM_OK)
    {
        retval = kStatus_KSS_Fail; 
    }
    /*
    if(kss_kose_uart_transceive((uint8_t *)"\x00\xa4\x04\x00\x01\x0a", 6, rcvbuf, &rcvlen) == false){
        retval = kStatus_KSS_Fail;
    }*/
    retval = kStatus_KSS_Success;

    const unsigned char fake_signature[] = {
        0x30, 0x45, 0x02, 0x21, 0x00, 0xC8, 0x44, 0xBD, 0x6A, 0x70, 0x84, 0xDD,
        0xB5, 0xF9, 0x11, 0x72, 0x33, 0xDC, 0xB7, 0xE1, 0xDE, 0xFA, 0x44, 0x83,
        0x2F, 0xB0, 0xCB, 0x28, 0xB2, 0xD3, 0x3C, 0xA4, 0x4D, 0xF9, 0x55, 0x02,
        0x20, 0x3B, 0x93, 0xB8, 0x89, 0x18, 0xE9, 0x71, 0xC1, 0xA0, 0x89, 0x9A,
        0x6A, 0x83, 0xF0, 0x12, 0x56, 0x8C, 0x37, 0x0B, 0xE4, 0xA8, 0x65, 0x67,
        0x39, 0x0A, 0x4E, 0xF7, 0xAB, 0x1D, 0xA7, 0xD9, 0xED, 0x00
    };
    const size_t fake_signature_len = 70;
    
    memcpy(signature, fake_signature, fake_signature_len);
    *signatureLen = fake_signature_len;

    status = SM_OK;

#if 1
#if KSSFTR_KOSE_ECC
    SE05x_ECSignatureAlgo_t ecSignAlgo = kSE05x_ECSignatureAlgo_NA;
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
        status     = Se05x_API_ECDSASign(&context->session->s_ctx,
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
            status = Se05x_API_RSADecrypt(&context->session->s_ctx,
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
            status = Se05x_API_RSADecrypt(&context->session->s_ctx,
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
            status = Se05x_API_RSADecrypt(&context->session->s_ctx,
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
            status = Se05x_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &u16parsedKeyByteLen);
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
            status = Se05x_API_RSADecrypt(&context->session->s_ctx,
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
#endif
    return retval;
}

kss_status_t kss_kose_asymmetric_encrypt(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA
    smStatus_t status                           = SM_NOT_OK;
    SE05x_RSAEncryptionAlgo_t rsaEncryptionAlgo = kose_get_rsa_encrypt_mode(context->algorithm);
    if (context->keyObject == NULL) {
        return kStatus_KSS_Fail;
    }
    status                                      = Se05x_API_RSAEncrypt(
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

    SE05x_RSAEncryptionAlgo_t rsaEncryptionAlgo = kose_get_rsa_encrypt_mode(context->algorithm);
    if (context->keyObject == NULL) {
        return retval;
    }
    status                                      = Se05x_API_RSADecrypt(
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
    SE05x_ECSignatureAlgo_t ecSignAlgo = kSE05x_ECSignatureAlgo_NA;
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
        status     = Se05x_API_ECDSASign(&context->session->s_ctx,
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
            status = Se05x_API_RSADecrypt(&context->session->s_ctx,
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
            status = Se05x_API_RSADecrypt(&context->session->s_ctx,
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
            status = Se05x_API_RSADecrypt(&context->session->s_ctx,
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
            status = Se05x_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &u16parsedKeyByteLen);
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
            status = Se05x_API_RSADecrypt(&context->session->s_ctx,
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
        SE05x_RSASignatureAlgo_t rsaSigningAlgo = kose_get_rsa_sign_hash_mode(context->algorithm);
        uint16_t key_size_bytes                 = 0;

        if (context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512 ||
            context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA512) {
            status = Se05x_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &key_size_bytes);
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

        status = Se05x_API_RSASign(
            &context->session->s_ctx, context->keyObject->keyId, rsaSigningAlgo, srcData, srcLen, destData, destLen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
        }
    } break;
#endif // KSSFTR_KOSE_RSA && KSS_HAVE_RSA
#if KSSFTR_KOSE_ECC && KSS_HAVE_EC_ED
    case kKSS_CipherType_EC_TWISTED_ED: {
        if (context->algorithm == kAlgorithm_KSS_SHA512) {
            SE05x_EDSignatureAlgo_t ecSignAlgo = kSE05x_EDSignatureAlgo_ED25519PURE_SHA_512;
            status                             = Se05x_API_EdDSASign(
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
    SE05x_Result_t result = kSE05x_Result_FAILURE;
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
        SE05x_ECSignatureAlgo_t ecSignAlgo = kose_get_ec_sign_hash_mode(context->algorithm);
        status                             = Se05x_API_ECDSAVerify(&context->session->s_ctx,
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

            status = Se05x_API_RSAEncrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kSE05x_RSAEncryptionAlgo_NO_PAD,
                signature,
                signatureLen,
                dec_data,
                &dec_len);
            if (status == SM_OK) {
                if (0 == emsa_decode_and_compare(context, dec_data, dec_len, digest, digestLen)) {
                    result = kSE05x_Result_SUCCESS;
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

            status = Se05x_API_RSAEncrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kSE05x_RSAEncryptionAlgo_NO_PAD,
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
                    result = kSE05x_Result_SUCCESS;
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

            status = Se05x_API_RSAEncrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kSE05x_RSAEncryptionAlgo_NO_PAD,
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
                    result = kSE05x_Result_SUCCESS;
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

            status = Se05x_API_RSAEncrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kSE05x_RSAEncryptionAlgo_NO_PAD,
                signature,
                signatureLen,
                dec_data,
                &dec_len);
            if (status == SM_OK) {
                status = Se05x_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &u16parsedKeyByteLen);
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
                        result = kSE05x_Result_SUCCESS;
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
        if (result == kSE05x_Result_SUCCESS) {
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
    SE05x_Result_t result = kSE05x_Result_FAILURE;
#endif

    switch (context->keyObject->cipherType) {
#if KSSFTR_KOSE_RSA && KSS_HAVE_RSA
    case kKSS_CipherType_RSA:
    case kKSS_CipherType_RSA_CRT: {
        SE05x_RSASignatureAlgo_t rsaSigningAlgo = kose_get_rsa_sign_hash_mode(context->algorithm);
        uint16_t key_size_bytes                 = 0;

        if (context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512 ||
            context->algorithm == kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA512) {
            status = Se05x_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &key_size_bytes);
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

        status = Se05x_API_RSAVerify(&context->session->s_ctx,
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
            SE05x_EDSignatureAlgo_t ecSignAlgo = kSE05x_EDSignatureAlgo_ED25519PURE_SHA_512;
            status                             = Se05x_API_EdDSAVerify(&context->session->s_ctx,
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
        if (result == kSE05x_Result_SUCCESS) {
            retval = kStatus_KSS_Success;
        }
    }
    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
    }
#endif

    return retval;
}

void kss_kose_asymmetric_context_free(kss_kose_asymmetric_t *context)
{
    memset(context, 0, sizeof(*context));
}