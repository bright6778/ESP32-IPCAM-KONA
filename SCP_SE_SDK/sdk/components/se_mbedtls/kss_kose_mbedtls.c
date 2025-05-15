#include "kss_kose_mbedtls.h"
//#include "kss_kose_session.h"
//#include "kss_kose_asymmetric.h"

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
    kss_status_t status = kStatus_KSS_Success;
    kss_asymmetric_t asymVerifyCtx;
    kss_object_t *kssObject = NULL;
    kss_algorithm_t algorithm;
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;

    kssObject = pax_ctx->grp.pKSSObject;

    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_KSS_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_KSS_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_KSS_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_KSS_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_KSS_SHA512;
        break;
    default:
        return 1;
    }

    LOG_I("%s: Verify using key '0x%08X'", __FUNCTION__, pax_ctx->grp.pKSSObject->keyId);

    status = kss_asymmetric_context_init(
        &asymVerifyCtx, kssObject->keyStore->session, kssObject, algorithm, kMode_KSS_Verify);
    if (status != kStatus_KSS_Success) {
        LOG_E(" kss_asymmetric_context_init verify context Failed...\n");
        return 1;
    }

    status = kss_asymmetric_verify_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, (uint8_t *)sig, sig_len);
    if (status != kStatus_KSS_Success) {
        LOG_E(" kss_asymmetric_verify_digest Failed...\n");
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
    size_t sig_size,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    LOGI(TAG, "kss_mbedtls_pk_sign");
    int ret            = 0;
    
    size_t u16_sig_len = 1024;
    kss_asymmetric_t asymVerifyCtx;
    kss_status_t status          = kStatus_KSS_Success;
    kss_object_t *kssObject      = NULL;
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;
    kss_algorithm_t algorithm;

    kssObject = pax_ctx->private_grp.pKSSObject;
    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_KSS_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_KSS_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_KSS_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_KSS_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_KSS_SHA512;
        break;
    default:
        return 1;
    }

    status = kss_asymmetric_context_init(&asymVerifyCtx, kssObject->keyStore->session, kssObject, algorithm, kMode_KSS_Sign);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, "kss_asymmetric_context_init verify context Failed...\n");
        return kStatus_KSS_Fail;
    }

    status = kss_asymmetric_sign_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, sig, &u16_sig_len);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, " kss_asymmetric_sign_digest Failed...\n");
        return kStatus_KSS_Fail;
    }

    *sig_len = u16_sig_len;

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

int kss_mbedtls_associate_keypair(mbedtls_pk_context *pkey, kss_object_t *pkeyObject)
{
    int ret               = 1;
    void *pax_ctx         = NULL;
    uint32_t objectId[16] = {
        0,
    };
    uint8_t objectIdLen = sizeof(objectId);
    kss_status_t status = kStatus_KSS_Fail;

    if (pkey->private_pk_ctx == NULL) {
        memset(pkey, 0, sizeof(*pkey));
    }

    if (pkeyObject->cipherType == kKSS_CipherType_EC_NIST_P || pkeyObject->cipherType == kKSS_CipherType_EC_NIST_K ||
        pkeyObject->cipherType == kKSS_CipherType_EC_BRAINPOOL ||
        pkeyObject->cipherType == kKSS_CipherType_EC_MONTGOMERY ||
        pkeyObject->cipherType == kKSS_CipherType_EC_TWISTED_ED) {
        LOGI(TAG, "Associating ECC key-pair %ld", pkeyObject->keyId);

        pkey->private_pk_info = &kose_mbedtls_eckeypair_pk_info;
        if (pkey->private_pk_ctx == NULL) {
            pax_ctx = (mbedtls_ecp_keypair *)mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
        }
        else {
            pax_ctx = pkey->private_pk_ctx;
        }
        if (pax_ctx == NULL) {
            LOGE(TAG, "Memory allocation for pax_ctx failed");
            goto cleanup;
        }
        ((mbedtls_ecp_keypair *)pax_ctx)->private_grp.pKSSObject = pkeyObject;
        /*
        status = kss_util_asn1_get_oid_from_kssObj(pkeyObject, objectId, &objectIdLen);
        if (status != kStatus_KSS_Success) {
            goto cleanup;
        }

        ((mbedtls_ecp_keypair *)pax_ctx)->private_grp.id = (mbedtls_ecp_group_id)get_group_id(objectId, objectIdLen);
        if (((mbedtls_ecp_keypair *)pax_ctx)->private_grp.id == MBEDTLS_ECP_DP_NONE) {
            LOGE(TAG, " kss_mbedtls_associate_keypair: Group id not found...\n");
            goto cleanup;
        }*/
    }
#ifdef MBEDTLS_RSA_ALT
    else if (pkeyObject->cipherType == kKSS_CipherType_RSA || pkeyObject->cipherType == kKSS_CipherType_RSA_CRT) {
        uint8_t pbKey[1024]  = {0};
        size_t pbKeyBitLen   = 0;
        size_t pbKeyBytetLen = sizeof(pbKey);
        uint8_t *modulus     = NULL;
        size_t modlen        = 0;
        uint8_t *pubExp      = NULL;
        size_t pubExplen     = 0;

        LOG_D("Associating RSA key-pair '0x%08X'", pkeyObject->keyId);

        pkey->pk_info = &ax_mbedtls_rsakeypair_info;
        if (pkey->pk_ctx == NULL) {
            pax_ctx = (mbedtls_rsa_context *)mbedtls_calloc(1, sizeof(mbedtls_rsa_context));
        }
        else {
            pax_ctx = pkey->pk_ctx;
        }
        if (pax_ctx == NULL) {
            LOG_E("Memory allocation for pax_ctx failed");
            goto cleanup;
        }
        ((mbedtls_rsa_context *)pax_ctx)->pKSSObject = pkeyObject;

        if (status != kStatus_KSS_Success) {
            status = kss_key_store_get_key(pkeyObject->keyStore, pkeyObject, pbKey, &pbKeyBytetLen, &pbKeyBitLen);
            goto cleanup;
        }

        status = kss_util_asn1_rsa_parse_public(pbKey, pbKeyBytetLen, &modulus, &modlen, &pubExp, &pubExplen);
        if (modulus != NULL) {
            KSS_FREE(modulus);
            modulus = NULL;
        }
        if (pubExp != NULL) {
            KSS_FREE(pubExp);
            pubExp = NULL;
        }
        if (status != kStatus_KSS_Success) {
            goto cleanup;
        }

        if ((SIZE_MAX / 8) < modlen) {
            goto cleanup;
        }
        ((mbedtls_rsa_context *)pax_ctx)->len = (modlen * 8);
    }
#endif /* MBEDTLS_RSA_ALT */
    else {
        goto cleanup;
    }
    if (pkey->private_pk_ctx == NULL) {
        pkey->private_pk_ctx = pax_ctx;
    }
    ret = 0;
cleanup:
    if ((pax_ctx != NULL) && (pkey->private_pk_ctx == NULL)) {
        mbedtls_free(pax_ctx);
    }
    return ret;
}



#if 0
int kss_mbedtls_associate_pubkey(mbedtls_pk_context *pkey, kss_object_t *pkeyObject)
{
    int ret               = 1;
    void *pax_ctx         = NULL;
    uint32_t objectId[16] = {
        0,
    };
    uint8_t objectIdLen = sizeof(objectId);
    kss_status_t status = kStatus_KSS_Fail;

    if (pkey->pk_ctx == NULL) {
        memset(pkey, 0, sizeof(*pkey));
    }

    if (pkeyObject->cipherType == kKSS_CipherType_EC_NIST_P || pkeyObject->cipherType == kKSS_CipherType_EC_NIST_K ||
        pkeyObject->cipherType == kKSS_CipherType_EC_BRAINPOOL ||
        pkeyObject->cipherType == kKSS_CipherType_EC_MONTGOMERY ||
        pkeyObject->cipherType == kKSS_CipherType_EC_TWISTED_ED) {
        LOG_D("Associating ECC public key '0x%08X'", pkeyObject->keyId);

        pkey->pk_info = &ax_mbedtls_ecpubkey_info;
        if (pkey->pk_ctx == NULL) {
            pax_ctx = (mbedtls_ecp_keypair *)mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
        }
        else {
            pax_ctx = pkey->pk_ctx;
        }
        if (pax_ctx == NULL) {
            LOG_E("Memory allocation for pax_ctx failed");
            goto cleanup;
        }

        if (pax_ctx == NULL) {
            return 1;
        }
        ((mbedtls_ecp_keypair *)pax_ctx)->grp.pKSSObject = pkeyObject;

        status = kss_util_asn1_get_oid_from_kssObj(pkeyObject, objectId, &objectIdLen);
        if (status != kStatus_KSS_Success) {
            goto cleanup;
        }

        ((mbedtls_ecp_keypair *)pax_ctx)->grp.id = (mbedtls_ecp_group_id)get_group_id(objectId, objectIdLen);
        if (((mbedtls_ecp_keypair *)pax_ctx)->grp.id == MBEDTLS_ECP_DP_NONE) {
            LOG_E(" kss_mbedtls_associate_pubkey: Group id not found...\n");
            goto cleanup;
        }
    }
#ifdef MBEDTLS_RSA_ALT
    else if (pkeyObject->cipherType == kKSS_CipherType_RSA || pkeyObject->cipherType == kKSS_CipherType_RSA_CRT) {
        uint8_t pbKey[1400]  = {0};
        size_t pbKeyBitLen   = 0;
        size_t pbKeyBytetLen = sizeof(pbKey);
        uint8_t *modulus     = NULL;
        size_t modlen        = 0;
        uint8_t *pubExp      = NULL;
        size_t pubExplen     = 0;

        pkey->pk_info = &ax_mbedtls_rsapubkey_info;
        LOG_D("Associating RSA public key '0x%08X'", pkeyObject->keyId);
        if (pkey->pk_ctx == NULL) {
            pax_ctx = (mbedtls_rsa_context *)mbedtls_calloc(1, sizeof(mbedtls_rsa_context));
        }
        else {
            pkey->pk_ctx = pax_ctx;
        }
        if (pax_ctx == NULL) {
            LOG_E("Memory allocation for pax_ctx failed");
            goto cleanup;
        }
        ((mbedtls_rsa_context *)pax_ctx)->pKSSObject = pkeyObject;

        status = kss_key_store_get_key(pkeyObject->keyStore, pkeyObject, pbKey, &pbKeyBytetLen, &pbKeyBitLen);
        if (status != kStatus_KSS_Success) {
            goto cleanup;
        }

        status = kss_util_asn1_rsa_parse_public(pbKey, pbKeyBytetLen, &modulus, &modlen, &pubExp, &pubExplen);
        if (modulus != NULL) {
            KSS_FREE(modulus);
            modulus = NULL;
        }
        if (pubExp != NULL) {
            KSS_FREE(pubExp);
            pubExp = NULL;
        }
        if (status != kStatus_KSS_Success) {
            goto cleanup;
        }

        if ((SIZE_MAX / 8) < modlen) {
            goto cleanup;
        }
        ((mbedtls_rsa_context *)pax_ctx)->len = (modlen * 8);
    }
#endif /* MBEDTLS_RSA_ALT */
    else {
        goto cleanup;
    }
    if (pkey->pk_ctx == NULL) {
        pkey->pk_ctx = pax_ctx;
    }
    ret = 0;
cleanup:
    if ((pax_ctx != NULL) && (pkey->pk_ctx == NULL)) {
        mbedtls_free(pax_ctx);
    }
    return ret;
}

int kss_mbedtls_associate_ecdhctx(
    mbedtls_ssl_handshake_params *handshake, kss_object_t *pKSSObject, kss_key_store_t *hostKs)
{
    kss_status_t status   = kStatus_KSS_Fail;
    uint32_t objectId[16] = {
        0,
    };
    uint8_t objectIdLen = sizeof(objectId);

    status = kss_util_asn1_get_oid_from_kssObj(pKSSObject, objectId, &objectIdLen);
    if (status != kStatus_KSS_Success) {
        return 1;
    }

    handshake->ecdh_ctx.grp.id = (mbedtls_ecp_group_id)get_group_id(objectId, objectIdLen);

    handshake->ecdh_ctx.grp.pKSSObject = pKSSObject;
    handshake->ecdh_ctx.grp.hostKs     = hostKs;
#if LOG_API_CALLS > 1
    LOG_I("Associating ECC key-pair '%d' for handshake.\r\n", key_index);
#endif
    return 0;
}
#endif