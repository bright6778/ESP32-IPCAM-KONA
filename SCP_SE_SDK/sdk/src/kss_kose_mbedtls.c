#include "kss_kose_mbedtls.h"
#include "kss_kose_session.h"
/*
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/pk.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
*/

static const char *TAG = "kss_kose_mbedtls.c";
/*
static mbedtls_pk_context client_key;

mbedtls_pk_context *cp_tls_get_client_key(void) {
    return &client_key;
}
*/
/*
void cp_tls_register_with_mbedtls(mbedtls_ssl_config *config)
{
    // 인증서 준비
    mbedtls_x509_crt *client_cert;
    mbedtls_pk_context *client_key;   // SDK 내부에 선언한 변수

    mbedtls_pk_init(client_key);
    client_key->private_pk_info = (const mbedtls_pk_info_t *)&kose_mbedtls_eckeypair_pk_info;
    //client_key->private_pk_ctx  = &se_key_object;

    // 인증서 설정
    mbedtls_ssl_conf_own_cert(config, client_cert, client_key);
}
*/

static size_t kss_eckey_get_bitlen(const void *ctx)
{
    return 256; //256-bit ECC 키
}

static int kss_eckeypair_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECKEY_DH || type == MBEDTLS_PK_ECDSA);
}

static int kss_ecpubkey_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECKEY_DH || type == MBEDTLS_PK_ECDSA);
}

static int kss_eckey_check_pair(const void *pub, const void *prv)
{
    return 0;
}

static void kss_eckeypair_free_func(void *ctx)
{
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;
    if (pax_ctx != NULL) {
        mbedtls_free(ctx);
    }
    return;
}

static void kss_ecpubkey_free_func(void *ctx)
{
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;
    if (pax_ctx != NULL) {
        mbedtls_free(ctx);
    }
    return;
}

// static 붙이기
int kss_eckey_verify(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    const unsigned char *sig,
    size_t sig_len)
{
    LOGI(TAG, "kss_eckey_verify");
    /*
    sss_status_t status = kStatus_SSS_Success;
    sss_asymmetric_t asymVerifyCtx;
    sss_object_t *sssObject = NULL;
    sss_algorithm_t algorithm;
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;

    sssObject = pax_ctx->grp.pSSSObject;

    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_SSS_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_SSS_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_SSS_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_SSS_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_SSS_SHA512;
        break;
    default:
        return 1;
    }

    LOG_I("%s: Verify using key '0x%08X'", __FUNCTION__, pax_ctx->grp.pSSSObject->keyId);

    status = sss_asymmetric_context_init(
        &asymVerifyCtx, sssObject->keyStore->session, sssObject, algorithm, kMode_SSS_Verify);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_context_init verify context Failed...\n");
        return 1;
    }

    status = sss_asymmetric_verify_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, (uint8_t *)sig, sig_len);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_verify_digest Failed...\n");
        return 1;
    }
    */
    return (0);
}

int kss_eckey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    LOGI(TAG, "kss_mbedtls_pk_sign");
    int ret            = 0;
    /*
    size_t u16_sig_len = 1024;
    sss_asymmetric_t asymVerifyCtx;
    sss_status_t status          = kStatus_SSS_Success;
    sss_object_t *sssObject      = NULL;
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;
    sss_algorithm_t algorithm;

    sssObject = pax_ctx->grp.pSSSObject;
    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_SSS_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_SSS_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_SSS_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_SSS_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_SSS_SHA512;
        break;
    default:
        return 1;
    }

    status =
        sss_asymmetric_context_init(&asymVerifyCtx, sssObject->keyStore->session, sssObject, algorithm, kMode_SSS_Sign);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_context_init verify context Failed...\n");
        return 1;
    }

    LOG_I("%s: Signing using key '0x%08lX'", __FUNCTION__, pax_ctx->grp.pSSSObject->keyId);

    status = sss_asymmetric_sign_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, sig, &u16_sig_len);
    if (status != kStatus_SSS_Success) {
        LOG_W(" sss_asymmetric_sign_digest Failed...\n");
        return 1;
    }

    *sig_len = u16_sig_len;
    */
    return (ret);
}
//const 나중에 붙여야 함.
mbedtls_pk_info_t kose_mbedtls_eckeypair_pk_info= {
    MBEDTLS_PK_ECKEY,
    "kose_EC_Keypair",
    &kss_eckey_get_bitlen,
    &kss_eckeypair_can_do,
    NULL,
    &kss_eckey_sign,
    NULL, // decrypt_func,
    NULL, // encrypt_func,
    &kss_eckey_check_pair,
    NULL, //&ax_eckey_alloc,
    &kss_eckeypair_free_func,
    NULL, //&ax_eckey_debug,
};

mbedtls_pk_info_t kose_mbedtls_ecpubkey_pk_info = {
    MBEDTLS_PK_ECKEY,
    "kose_EC_pubkey",
    &kss_eckey_get_bitlen,
    &kss_eckeypair_can_do,
    &kss_eckey_verify,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &kss_ecpubkey_free_func,
    NULL,
};

void setup_se_default_pk_info()
{
    // 기본 구조 가져오기
    const mbedtls_pk_info_t *default_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    memcpy(&kose_mbedtls_eckeypair_pk_info, default_info, sizeof(mbedtls_pk_info_t));
    memcpy(&kose_mbedtls_ecpubkey_pk_info, default_info, sizeof(mbedtls_pk_info_t));
}
#if 0
kss_status_t kss_kose_asymmetric_sign_digest(
    kss_kose_asymmetric_t *context, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    smStatus_t status   = SM_NOT_OK;

#if SSSFTR_SE05X_ECC
    SE05x_ECSignatureAlgo_t ecSignAlgo = kSE05x_ECSignatureAlgo_NA;
#endif

#if SSSFTR_SE05X_ECC || SSSFTR_SE05X_RSA
    if (kStatus_SSS_Success != se05x_check_input_len(digestLen, context->algorithm)) {
        LOG_E("Algorithm and digest length do not match");
        return kStatus_SSS_Fail;
    }
#endif

    switch (context->keyObject->cipherType) {
#if SSSFTR_SE05X_ECC
    case kSSS_CipherType_EC_NIST_P:
#if SSS_HAVE_EC_NIST_K
    case kSSS_CipherType_EC_NIST_K:
#endif
#if SSS_HAVE_EC_BP
    case kSSS_CipherType_EC_BRAINPOOL:
#endif
    {
        ecSignAlgo = se05x_get_ec_sign_hash_mode(context->algorithm);
        status     = Se05x_API_ECDSASign(&context->session->s_ctx,
            context->keyObject->keyId,
            ecSignAlgo,
            digest,
            digestLen,
            signature,
            signatureLen);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_SSS_ApduThroughputError;
        }
    } break;
#if SSS_HAVE_SE05X_VER_GTE_07_02 && SSS_HAVE_EC_MONT
    case kSSS_CipherType_EC_MONTGOMERY: {
        LOG_W(
            "Sign operation is not supported for "
            "kSSS_CipherType_EC_MONTGOMERY curve");
        return kStatus_SSS_Fail;
    } break;
#endif // SSS_HAVE_SE05X_VER_GTE_07_02 && SSS_HAVE_EC_MONT
#endif //SSSFTR_SE05X_ECC
#if SSSFTR_SE05X_RSA && SSS_HAVE_RSA && !SSS_HAVE_HOSTCRYPTO_NONE
    case kSSS_CipherType_RSA:
    case kSSS_CipherType_RSA_CRT: {
        if ((context->algorithm <= kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512) &&
            (context->algorithm >= kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1)) {
            /* Perform EMSA encoding on input data and and RSA decrypt on emsa data --> RSA sign without hash */
            /* clang-format off */
            uint8_t emsa_data[512] = {0,}; /* MAX - SHA512*/
            size_t emsa_len = sizeof(emsa_data);
            uint8_t encode_ret = 0;
            /* clang-format on */

            encode_ret = emsa_encode(context, digest, digestLen, emsa_data, &emsa_len);
            if (0 != encode_ret) {
                if (encode_ret == 2) {
                    return kStatus_SSS_ApduThroughputError;
                }
                else {
                    return kStatus_SSS_Fail;
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
                retval = kStatus_SSS_ApduThroughputError;
            }
        }
        else if ((context->algorithm <= kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512) &&
                 (context->algorithm >= kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1)) {
            uint8_t encode_ret = 0;
            /* Perform PKCS1-v15 encoding on input data and and RSA decrypt on PKCS1-v15 data --> RSA sign without hash */
            /* clang-format off */
            uint8_t pkcs1v15_encode_data[512] = {0,}; /* MAX - SHA512*/
            size_t encode_data_len = sizeof(pkcs1v15_encode_data);
            /* clang-format on */

            encode_ret = pkcs1_v15_encode(context, digest, digestLen, pkcs1v15_encode_data, &encode_data_len);
            if (0 != encode_ret) {
                if (encode_ret == 2) {
                    return kStatus_SSS_ApduThroughputError;
                }
                else {
                    return kStatus_SSS_Fail;
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
                retval = kStatus_SSS_ApduThroughputError;
            }
        }
        else if (context->algorithm == kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH) {
            uint8_t encode_ret = 0;
            /* Perform PKCS1-v15 encoding on input data and and RSA decrypt on PKCS1-v15 data --> RSA sign without hash */
            /* clang-format off */
            uint8_t pkcs1v15_encode_data[512] = {0,}; /* MAX - SHA512*/
            size_t encode_data_len = sizeof(pkcs1v15_encode_data);
            /* clang-format on */

            encode_ret = pkcs1_v15_encode_no_hash(context, digest, digestLen, pkcs1v15_encode_data, &encode_data_len);
            if (0 != encode_ret) {
                if (encode_ret == 2) {
                    return kStatus_SSS_ApduThroughputError;
                }
                else {
                    return kStatus_SSS_Fail;
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
                retval = kStatus_SSS_ApduThroughputError;
            }
        }
        else if (context->algorithm == kAlgorithm_SSS_RSASSA_NO_PADDING) {
            uint8_t padded_data[512] = {0};
            size_t padded_len        = sizeof(padded_data);

            size_t parsedKeyByteLen      = 0;
            uint16_t u16parsedKeyByteLen = 0;
            status = Se05x_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &u16parsedKeyByteLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                return kStatus_SSS_ApduThroughputError;
            }
            parsedKeyByteLen = u16parsedKeyByteLen;
            if (status != SM_OK) {
                return kStatus_SSS_Fail;
            }

            if (digestLen <= parsedKeyByteLen && digestLen > 0) {
                memset(padded_data, 0x00, padded_len);
                memcpy(&padded_data[parsedKeyByteLen - digestLen], &digest[0], digestLen);
                padded_len = parsedKeyByteLen;
            }
            else {
                return kStatus_SSS_Fail;
            }
            status = Se05x_API_RSADecrypt(&context->session->s_ctx,
                context->keyObject->keyId,
                kSE05x_RSAEncryptionAlgo_NO_PAD,
                padded_data,
                padded_len,
                signature,
                signatureLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_SSS_ApduThroughputError;
            }
        }
        else {
            LOG_E("Selected padding is not supported for RSA Sign in SE050");
            return kStatus_SSS_Fail;
        }
    } break;
#endif // SSSFTR_SE05X_RSA && SSS_HAVE_RSA && !SSS_HAVE_HOSTCRYPTO_NONE
    default:
        break;
    }

    if (status == SM_OK) {
        retval = kStatus_SSS_Success;
    }

    return retval;
}
#endif