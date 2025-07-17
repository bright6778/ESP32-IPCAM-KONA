/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#include "kona_kss_api.h"
#include "kona_kss_keyid_map.h"
#include "kona_kss_mbedtls_types.h"
#include "kona_kss_kose_types.h"
#include "ensure.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "kss_kose_mbedtls.h"
#include "kona_kss_util_asn1_der.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/pk.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

static const char *TAG = "kss_kose_mbedtls.c";

#define MAX_KEY_OBJ_COUNT KS_N_ENTIRES
#define MAX_FILE_NAME_SIZE 255
#define MAX_SHARED_SECRET_DERIVED_DATA 255
#define BEGIN_PRIVATE "-----BEGIN PRIVATE KEY-----\n"
#define END_PRIVATE "\n-----END PRIVATE KEY-----"
#define BEGIN_PUBLIC "-----BEGIN PUBLIC KEY-----\n"
#define END_PUBLIC "\n-----END PUBLIC KEY-----"

#define CIPHER_BLOCK_SIZE 16

static size_t kss_eckey_get_bitlen(const void *ctx)
{
    return 256; //256-bit ECC 키
}

static int kss_eckeypair_can_do(mbedtls_pk_type_t type)
{
    int ret = 0;
    if (type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECKEY_DH || type == MBEDTLS_PK_ECDSA){
        ret = 1;
    }
    return ret;
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
    LOGD(TAG, "kss_eckey_verify");
    kss_status_t status = kStatus_KSS_Success;
    kss_asymmetric_t asymVerifyCtx;
    kss_object_t *kssObject = NULL;
    kss_algorithm_t algorithm;
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;
    mbedtls_pk_context *pcheck_ctx = (mbedtls_pk_context *)ctx;

    if (pcheck_ctx->pk_info->name == kose_mbedtls_ecpubkey_pk_info.name &&
        pcheck_ctx->pk_ctx != NULL &&
        pcheck_ctx->pk_ctx != ctx)
    {
        LOGD(TAG, "[WARN] ctx is pk_context*, fixing...");
        LOGD(TAG, "[WARN] pk_info->name of ctx : %s", pcheck_ctx->pk_info->name);
        ctx = pcheck_ctx->pk_ctx;
        pax_ctx = (mbedtls_ecp_keypair *)ctx;
    }

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
    
    status = kss_asymmetric_context_init(
        &asymVerifyCtx, kssObject->keyStore->session, kssObject, algorithm, kMode_KSS_Verify);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, " kss_asymmetric_context_init verify context Failed...\n");
        return 1;
    }

    status = kss_asymmetric_verify_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, (uint8_t *)sig, sig_len);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, " kss_asymmetric_verify_digest Failed...\n");
        return 1;
    }

    return 0;
}

static int kss_eckey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t sig_size,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    LOGD(TAG, "kss_mbedtls_pk_sign");
    int ret            = 0;
    
    size_t u16_sig_len = 1024;
    kss_asymmetric_t asymVerifyCtx;
    kss_status_t status          = kStatus_KSS_Success;
    kss_object_t *kssObject      = NULL;
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;
    mbedtls_pk_context *pcheck_ctx = (mbedtls_pk_context *)ctx;
    kss_algorithm_t algorithm;

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

    if (pcheck_ctx->pk_info->name == kose_mbedtls_eckeypair_pk_info.name &&
        pcheck_ctx->pk_ctx != NULL &&
        pcheck_ctx->pk_ctx != ctx)
    {
        LOGD(TAG, "[WARN] ctx is pk_context*, fixing...");
        LOGD(TAG, "[WARN] pk_info->name of ctx : %s", pcheck_ctx->pk_info->name);
        ctx = pcheck_ctx->pk_ctx;
        pax_ctx = (mbedtls_ecp_keypair *)ctx;
    }

    kssObject = pax_ctx->grp.pKSSObject;
    
    if(kssObject == NULL){
        return kStatus_KSS_Fail;
    }

    if(kssObject->keyStore->session == NULL){
        return kStatus_KSS_Fail;
    }

    status = kss_asymmetric_context_init(&asymVerifyCtx, kssObject->keyStore->session, kssObject, algorithm, kMode_KSS_Sign);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, "kss_asymmetric_context_init Failed...\n");
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


const mbedtls_pk_info_t kose_mbedtls_eckeypair_pk_info= {
    MBEDTLS_PK_ECKEY,
    "kose_EC_Keypair",
    &kss_eckey_get_bitlen,
    &kss_eckeypair_can_do,
    NULL,
    &kss_eckey_sign,
    NULL, // decrypt_func,
    NULL, // encrypt_func,
    &kss_eckey_check_pair,
    NULL, //&kss_eckey_alloc,
    &kss_eckeypair_free_func,
    NULL, //&ax_eckey_debug,
};

const mbedtls_pk_info_t kose_mbedtls_ecpubkey_pk_info = {
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


int kss_mbedtls_verify_sign(mbedtls_pk_context *pkey, kss_object_t *pkeyObject)
{
    int ret               = 1;
    void *pax_ctx         = NULL;
    
    if (pkey->pk_ctx == NULL) {
        memset(pkey, 0, sizeof(*pkey));
    }

    if (pkeyObject->cipherType == kKSS_CipherType_EC_NIST_P || pkeyObject->cipherType == kKSS_CipherType_EC_NIST_K ||
        pkeyObject->cipherType == kKSS_CipherType_EC_BRAINPOOL ||
        pkeyObject->cipherType == kKSS_CipherType_EC_MONTGOMERY ||
        pkeyObject->cipherType == kKSS_CipherType_EC_TWISTED_ED) {
        
        pkey->pk_info = &kose_mbedtls_ecpubkey_pk_info;
        if (pkey->pk_ctx == NULL) {
            pax_ctx = (mbedtls_ecp_keypair *)mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
        }
        else {
            pax_ctx = pkey->pk_ctx;
        }
        if (pax_ctx == NULL) {
            LOGE(TAG, "Memory allocation for pax_ctx failed");
            goto cleanup;
        }

        if (pax_ctx == NULL) {
            return 1;
        }
        ((mbedtls_ecp_keypair *)pax_ctx)->grp.pKSSObject = pkeyObject;
        ((mbedtls_ecp_keypair *)pax_ctx)->grp.id = MBEDTLS_ECP_DP_SECP256R1;
    }
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

    //handshake->ecdh_ctx.grp.id = (mbedtls_ecp_group_id)get_group_id(objectId, objectIdLen);

    //handshake->ecdh_ctx.grp.pKSSObject = pKSSObject;
    //handshake->ecdh_ctx.grp.hostKs     = hostKs;

    return 0;
}

int kss_mbedtls_sign(mbedtls_pk_context *pkey, kss_object_t *pkeyObject)
{
    int ret               = 1;
    void *pax_ctx         = NULL;
    
    if (pkey->pk_ctx == NULL) {
        memset(pkey, 0, sizeof(*pkey));
    }
    
    if (pkeyObject->cipherType == kKSS_CipherType_EC_NIST_P || pkeyObject->cipherType == kKSS_CipherType_EC_NIST_K ||
        pkeyObject->cipherType == kKSS_CipherType_EC_BRAINPOOL ||
        pkeyObject->cipherType == kKSS_CipherType_EC_MONTGOMERY ||
        pkeyObject->cipherType == kKSS_CipherType_EC_TWISTED_ED) {
        
        pkey->pk_info = &kose_mbedtls_eckeypair_pk_info;
        if (pkey->pk_ctx == NULL) {
            pax_ctx = (mbedtls_ecp_keypair *)mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
        }
        else {
            pax_ctx = pkey->pk_ctx;
        }
        if (pax_ctx == NULL) {
            LOGE(TAG, "Memory allocation for pax_ctx failed");
            goto cleanup;
        }
        
        ((mbedtls_ecp_keypair *)pax_ctx)->grp.pKSSObject = pkeyObject;
        ((mbedtls_ecp_keypair *)pax_ctx)->grp.id = MBEDTLS_ECP_DP_SECP256R1;
    }
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

int kss_mbedtls_se_random(void *p_rng, unsigned char *output, size_t output_len){
    kss_status_t kStatus = kStatus_KSS_Fail;
    kss_rng_context_t *ctx = (kss_rng_context_t *) p_rng;

    kStatus = kss_rng_get_random(ctx, output, output_len);
    if (kStatus_KSS_Success != kStatus) {
        return -1;
    }  
    return 0;
}

int kss_mbedtls_parse_keyfile(const uint8_t *pem, size_t pem_len, uint8_t *d_buf, size_t *d_bufLen){
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    size_t keylen = 0;

    int ret = mbedtls_pk_parse_key(&pk, pem, pem_len, NULL, 0, NULL, NULL);
    if (ret != 0) {
        char err[128];
        mbedtls_strerror(ret, err, sizeof(err));
        LOGE(TAG, "parse failed: %s\n", err);
        mbedtls_pk_free(&pk);
        return ret;
    }

    if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY) {
        mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pk);
        keylen  = mbedtls_mpi_size(&ec->d);
        mbedtls_mpi_write_binary(&ec->d, d_buf, keylen);
    } else {
        LOGE(TAG,"Not an EC private key\n");
    }

    *d_bufLen = keylen;

    mbedtls_pk_free(&pk);

    return ret;
}

int kss_mbedtls_parse_crt_getpublickey(const uint8_t *cert, size_t cert_len, uint8_t *pub_buf, size_t *pub_len){
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    int ret = mbedtls_x509_crt_parse(&crt, cert, cert_len);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return ret;
    }

    mbedtls_pk_context *pk = &crt.pk;
    if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_ECKEY) {
        mbedtls_x509_crt_free(&crt);
        return -1; // not EC key
    }

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*pk);

    size_t x_len = mbedtls_mpi_size(&ec->Q.X);
    size_t y_len = mbedtls_mpi_size(&ec->Q.Y);
    size_t total = x_len + y_len;

    if (*pub_len < total) {
        mbedtls_x509_crt_free(&crt);
        return -2; // buffer too small
    }

    mbedtls_mpi_write_binary(&ec->Q.X, pub_buf, x_len);
    mbedtls_mpi_write_binary(&ec->Q.Y, pub_buf + x_len, y_len);

    kss_debug_showframe("Q.X", pub_buf, x_len);
    kss_debug_showframe("Q.Y", pub_buf, x_len+y_len);
    LOGD(TAG, "x_len : %zu", x_len);
    LOGD(TAG, "y_len : %zu", y_len);

    *pub_len = total;

    mbedtls_x509_crt_free(&crt);
    return 0;
}