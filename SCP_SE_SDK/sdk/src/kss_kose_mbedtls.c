#include "kss_kose_mbedtls.h"
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
    LOGI(TAG, "kss_eckey_get_bitlen");
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

static int kss_eckey_verify(void *ctx,
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

static int kss_eckey_sign(void *ctx,
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

const kose_mbedtls_pk_info_t kose_mbedtls_eckeypair_pk_info= {
    MBEDTLS_PK_ECKEY,
    "kose_EC_Keypair",
    &kss_eckey_get_bitlen,
    &kss_eckeypair_can_do,
    NULL,
    //&sss_eckey_sign,
    &kss_eckey_sign,
    NULL, // decrypt_func,
    NULL, // encrypt_func,
    &kss_eckey_check_pair,
    NULL, //&ax_eckey_alloc,
    &kss_eckeypair_free_func,
    NULL, //&ax_eckey_debug,
};

const kose_mbedtls_pk_info_t kose_mbedtls_ecpubkey_pk_info = {
    MBEDTLS_PK_ECKEY,
    "kose_EC_pubkey",
    &kss_eckey_get_bitlen,
    &kss_eckeypair_can_do,
    //&sss_eckey_verify,
    &kss_eckey_verify,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &kss_ecpubkey_free_func,
    NULL,
};

