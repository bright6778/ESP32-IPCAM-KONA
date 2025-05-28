#include "kona_kss_api.h"
#include "kona_kss_keyid_map.h"
#include "kona_kss_mbedtls_types.h"
#include "kona_kss_kose_types.h"
#include "ensure.h"
#include "mbedtls/base64.h"
#include "kss_kose_mbedtls.h"
#include "kona_kss_util_asn1_der.h"
//#include "kss_kose_session.h"
//#include "kss_kose_asymmetric.h"


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
#define DES_BLOCK_SIZE (MBEDTLS_KEY_LENGTH_DES / 8)

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
    int ret = 0;
    if (type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECKEY_DH || type == MBEDTLS_PK_ECDSA){
        ret = 1;
    }
    return ret;
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

static void *kss_eckey_alloc(void)
{
    LOGD(TAG, "kss_eckey_alloc");
    mbedtls_ecp_keypair *ctx = calloc(1, sizeof(mbedtls_ecp_keypair));
    if (!ctx)
        return NULL;
    return ctx;
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

    //LOGI(TAG, "%s: Verify using key '0x%08X'", __FUNCTION__, pax_ctx->grp.pKSSObject->keyId);

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

    return (0);
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

    if (pcheck_ctx->pk_info == &kose_mbedtls_eckeypair_pk_info &&
        pcheck_ctx->pk_ctx != NULL &&
        pcheck_ctx->pk_ctx != ctx)
    {
        LOGD(TAG, "[WARN] ctx is pk_context*, fixing...");
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

void setup_se_default_pk_info()
{
    // 기본 구조 가져오기
    const mbedtls_pk_info_t *default_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    memcpy(&kose_mbedtls_eckeypair_pk_info, default_info, sizeof(mbedtls_pk_info_t));
    memcpy(&kose_mbedtls_ecpubkey_pk_info, default_info, sizeof(mbedtls_pk_info_t));
}

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
        LOGD(TAG, "Associating ECC public key '0x%08" PRIX32 "'", pkeyObject->keyId);

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

        /*
        status = kss_util_asn1_get_oid_from_kssObj(pkeyObject, objectId, &objectIdLen);
        if (status != kStatus_KSS_Success) {
            goto cleanup;
        }

        ((mbedtls_ecp_keypair *)pax_ctx)->grp.id = (mbedtls_ecp_group_id)get_group_id(objectId, objectIdLen);
        if (((mbedtls_ecp_keypair *)pax_ctx)->grp.id == MBEDTLS_ECP_DP_NONE) {
            LOGE(TAG, " kss_mbedtls_associate_pubkey: Group id not found...\n");
            goto cleanup;
        }
        */
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
            LOGE(TAG, "Memory allocation for pax_ctx failed");
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

    //handshake->ecdh_ctx.grp.id = (mbedtls_ecp_group_id)get_group_id(objectId, objectIdLen);

    //handshake->ecdh_ctx.grp.pKSSObject = pKSSObject;
    //handshake->ecdh_ctx.grp.hostKs     = hostKs;
#if LOG_API_CALLS > 1
    LOG_I("Associating ECC key-pair '%d' for handshake.\r\n", key_index);
#endif
    return 0;
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

    if (pkey->pk_ctx == NULL) {
        memset(pkey, 0, sizeof(*pkey));
    }
    
    if (pkeyObject->cipherType == kKSS_CipherType_EC_NIST_P || pkeyObject->cipherType == kKSS_CipherType_EC_NIST_K ||
        pkeyObject->cipherType == kKSS_CipherType_EC_BRAINPOOL ||
        pkeyObject->cipherType == kKSS_CipherType_EC_MONTGOMERY ||
        pkeyObject->cipherType == kKSS_CipherType_EC_TWISTED_ED) {
        LOGD(TAG, "Associating ECC key-pair '0x%08" PRIX32 "'", pkeyObject->keyId);

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
            LOGE(TAG, "Memory allocation for pax_ctx failed");
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

static kss_status_t kss_mbedtls_set_key(
    kss_mbedtls_object_t *keyObject, const uint8_t *data, size_t dataLen, size_t keyBitLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_SW_ECC || KSSFTR_SW_RSA
    size_t base64_olen;
    int ret;
    char pem_format[2048];

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
#endif
    switch (keyObject->objectType) {
    case kKSS_KeyPart_Default:
        ENSURE_OR_GO_EXIT(dataLen <= keyObject->contents_max_size);
        if (data != NULL) /* For empty certificate */
            memcpy(keyObject->contents, data, dataLen);
        keyObject->contents_size = dataLen;
        keyObject->keyBitLen     = keyBitLen;
        retval                   = kStatus_KSS_Success;
        break;
#if KSSFTR_SW_ECC || KSSFTR_SW_RSA
    case kKSS_KeyPart_Private:
    case kKSS_KeyPart_Pair: {
        mbedtls_pk_context *pk = (mbedtls_pk_context *)keyObject->contents;
        if (keyObject->cipherType == kKSS_CipherType_EC_MONTGOMERY) {
            mbedtls_ecp_keypair *pEcpPrv = NULL;
            kss_status_t asn_retval      = kStatus_KSS_Fail;
            ret                          = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
            ENSURE_OR_GO_EXIT(ret == 0);

            pEcpPrv = mbedtls_pk_ec(*pk);
            ENSURE_OR_GO_EXIT(pEcpPrv);

            if (keyBitLen == 256) {
                ret = mbedtls_ecp_group_load(&pEcpPrv->grp, MBEDTLS_ECP_DP_CURVE25519);
            }
            else if (keyBitLen == 448) {
                ret = mbedtls_ecp_group_load(&pEcpPrv->grp, MBEDTLS_ECP_DP_CURVE448);
            }
            else {
                ret = 1;
            }
            ENSURE_OR_GO_EXIT(ret == 0);

#ifdef MBEDTLS_DO_LITTLE_ENDIAN // Reverse Endianness
            {
                size_t i                   = 0;
                uint16_t publicKeyIndex    = 0;
                size_t publicKeyLen        = 0;
                uint16_t privateKeyIndex   = 0;
                size_t privateKeyLen       = 0;
                uint8_t pubKeyReversed[64] = {
                    0,
                };
                const uint8_t *pPublicKey  = NULL;
                uint8_t prvKeyReversed[64] = {
                    0,
                };
                const uint8_t *pPrivateKey = NULL;

                asn_retval = kss_util_rfc8410_asn1_get_ec_pair_key_index(
                    data, dataLen, &publicKeyIndex, &publicKeyLen, &privateKeyIndex, &privateKeyLen);
                if (asn_retval != kStatus_KSS_Success) {
                    LOG_W("error in kss_util_rfc8410_asn1_get_ec_pair_key_index");
                    goto exit;
                }

                while (i < publicKeyLen) {
                    ENSURE_OR_GO_EXIT((UINT_MAX - publicKeyIndex) >= publicKeyLen);
                    pubKeyReversed[i] = data[publicKeyIndex + publicKeyLen - i - 1];
                    i++;
                }
                pPublicKey = &pubKeyReversed[0];

                i = 0;
                while (i < privateKeyLen) {
                    ENSURE_OR_GO_EXIT((UINT_MAX - publicKeyIndex) >= publicKeyLen);
                    prvKeyReversed[i] = data[privateKeyIndex + privateKeyLen - i - 1];
                    i++;
                }

                /* RFC 7748, Sec 5 Par 5*/
                if (keyBitLen == 256) {
                    prvKeyReversed[privateKeyLen - 1] = prvKeyReversed[privateKeyLen - 1] & 0xF8;
                    prvKeyReversed[0]                 = prvKeyReversed[0] & 0x7F;
                    prvKeyReversed[0]                 = prvKeyReversed[0] | 0x40;
                }
                else {
                    prvKeyReversed[privateKeyLen - 1] = prvKeyReversed[privateKeyLen - 1] & 0xFC;
                    prvKeyReversed[0]                 = prvKeyReversed[0] | 0x80;
                }

                pPrivateKey = &prvKeyReversed[0];

                ret = mbedtls_mpi_read_binary(&pEcpPrv->d, pPrivateKey, privateKeyLen);
                ENSURE_OR_GO_EXIT(ret == 0);

                ret = mbedtls_mpi_read_binary(&pEcpPrv->Q.X, pPublicKey, publicKeyLen);
                ENSURE_OR_GO_EXIT(ret == 0);

                ret = mbedtls_mpi_lset(&pEcpPrv->Q.Z, 1);
                ENSURE_OR_GO_EXIT(ret == 0);

                retval = kStatus_KSS_Success;
            }
#else
            ret = mbedtls_mpi_read_binary(&pEcpPrv->d, data, dataLen);
            ENSURE_OR_GO_EXIT(ret == 0);
            retval = kStatus_KSS_Success;
#endif
        }
        else {
            //ret = mbedtls_pk_parse_key(pk, data, dataLen, NULL, 0);
            ret = mbedtls_pk_parse_key(pk, data, dataLen, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
            (ret == 0) ? (retval = kStatus_KSS_Success) : (retval = kStatus_KSS_Fail);
        }
    } break;
    case kKSS_KeyPart_Public: {
        // Sizeof base64_format should be limited to sizeof(pem_format) minus BEGIN_PUBLIC and END_PUBLIC
        // SIMW-2696.
        uint8_t base64_format[1996] = {0};
        mbedtls_pk_context *pk      = (mbedtls_pk_context *)keyObject->contents;
        if (keyObject->cipherType == kKSS_CipherType_EC_MONTGOMERY) {
            mbedtls_ecp_keypair *pEcpPub = NULL;

            ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
            ENSURE_OR_GO_EXIT(ret == 0);

            pEcpPub = mbedtls_pk_ec(*pk);
            ENSURE_OR_GO_EXIT(pEcpPub);
            if (keyBitLen == 256) {
                ret = mbedtls_ecp_group_load(&pEcpPub->grp, MBEDTLS_ECP_DP_CURVE25519);
            }
            else if (keyBitLen == 448) {
                ret = mbedtls_ecp_group_load(&pEcpPub->grp, MBEDTLS_ECP_DP_CURVE448);
            }
            else {
                ret = 1;
            }
            ENSURE_OR_GO_EXIT(ret == 0);

#ifdef MBEDTLS_DO_LITTLE_ENDIAN // Reverse Endianness
            {
                size_t i                   = 0;
                size_t publicKeyIndex      = 0;
                size_t publicKeyLen        = dataLen;
                size_t nByteKey            = 32; // Corresponds to kSE05x_ECCurve_ECC_MONT_DH_25519
                uint8_t pubKeyReversed[64] = {
                    0,
                };
                const uint8_t *pPublicKey = NULL;
// #define TMP_ENDIAN_VERBOSE
#ifdef TMP_ENDIAN_VERBOSE
                printf("Pub Key Before Reverse & header strip:\n");
                ENSURE_OR_GO_EXIT(dataLen >= (publicKeyIndex + publicKeyLen));
                for (size_t z = 0; z < publicKeyLen; z++) {
                    printf("%02X.", data[publicKeyIndex + z]);
                }
                printf("\n");
                printf("keyBitLen = %d\n", (int)keyBitLen);
#endif
                if (keyBitLen == 256) {
                    publicKeyIndex = der_ecc_mont_dh_25519_header_len;
                    ENSURE_OR_GO_EXIT(publicKeyLen >= der_ecc_mont_dh_25519_header_len);
                    publicKeyLen -= der_ecc_mont_dh_25519_header_len;
                }
                else {
                    nByteKey       = 56;
                    publicKeyIndex = der_ecc_mont_dh_448_header_len;
                    publicKeyLen -= der_ecc_mont_dh_448_header_len;
                }
                ENSURE_OR_GO_EXIT((UINT_MAX - publicKeyIndex) >= publicKeyLen);
                ENSURE_OR_GO_EXIT(dataLen >= (publicKeyIndex + publicKeyLen));
                while (i < nByteKey) {
                    ENSURE_OR_GO_EXIT((publicKeyIndex + publicKeyLen) > i);
                    pubKeyReversed[i] = data[publicKeyIndex + publicKeyLen - i - 1];
                    i++;
                }
                pPublicKey = &pubKeyReversed[0];

#ifdef TMP_ENDIAN_VERBOSE
                printf("Pub Key After Reverse:\n");
                for (size_t z = 0; z < publicKeyLen; z++) {
                    printf("%02X.", pPublicKey[z]);
                }
                printf("\n");
#endif
                ret = mbedtls_mpi_read_binary(&pEcpPub->Q.X, pPublicKey, publicKeyLen);
            }
#else
            ret = mbedtls_mpi_read_binary(&pEcpPub->Q.X, data, dataLen);
#endif // Reverse Endianess

            (ret == 0) ? (retval = kStatus_KSS_Success) : (retval = kStatus_KSS_Fail);

            if (retval == kStatus_KSS_Success) {
                ret = mbedtls_mpi_lset(&pEcpPub->Q.Z, 1);
                (ret == 0) ? (retval = kStatus_KSS_Success) : (retval = kStatus_KSS_Fail);
            }
        }
        else {
            ret = mbedtls_base64_encode(base64_format, sizeof(base64_format), &base64_olen, data, dataLen);
            if (snprintf(pem_format, sizeof(pem_format), BEGIN_PUBLIC "%s" END_PUBLIC, base64_format) < 0) {
                retval = kStatus_KSS_Fail;
                goto exit;
            }
            ret = mbedtls_pk_parse_public_key(pk, (const uint8_t *)pem_format, strlen(pem_format) + 1);
            (ret == 0) ? (retval = kStatus_KSS_Success) : (retval = kStatus_KSS_Fail);
        }
    } break;
#endif // KSSFTR_SW_ECC || KSSFTR_SW_RSA
    default:
        retval = kStatus_KSS_Fail;
        LOGE(TAG, "Key type not supported");
        break;
    }
exit:
    return retval;
}

static mbedtls_md_type_t kss_mbedtls_set_padding_get_hash(kss_algorithm_t algorithm, mbedtls_pk_context *pKey)
{
    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
    switch (algorithm) {
    case kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA1:
    case kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA1:
    case kAlgorithm_KSS_ECDSA_SHA1:
    case kAlgorithm_KSS_SHA1: {
        md_alg = MBEDTLS_MD_SHA1;
    } break;
    case kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA224:
    case kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA224:
    case kAlgorithm_KSS_ECDSA_SHA224:
    case kAlgorithm_KSS_SHA224: {
        md_alg = MBEDTLS_MD_SHA224;
    } break;
    case kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA256:
    case kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA256:
    case kAlgorithm_KSS_ECDSA_SHA256:
    case kAlgorithm_KSS_SHA256: {
        md_alg = MBEDTLS_MD_SHA256;
    } break;
    case kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA384:
    case kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA384:
    case kAlgorithm_KSS_ECDSA_SHA384:
    case kAlgorithm_KSS_SHA384: {
        md_alg = MBEDTLS_MD_SHA384;
    } break;
    case kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512:
    case kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA512:
    case kAlgorithm_KSS_ECDSA_SHA512:
    case kAlgorithm_KSS_SHA512: {
        md_alg = MBEDTLS_MD_SHA512;
    } break;
    default:
        md_alg = MBEDTLS_MD_NONE;
        break;
    }

    if (algorithm >= kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA1 &&
        algorithm <= kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA512) {
        mbedtls_rsa_set_padding(mbedtls_pk_rsa(*pKey), MBEDTLS_RSA_PKCS_V21, md_alg);
    }
    else if ((algorithm >= kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA1 &&
                 algorithm <= kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512) ||
             algorithm == kAlgorithm_KSS_RSASSA_PKCS1_V1_5_NO_HASH) {
        mbedtls_rsa_set_padding(mbedtls_pk_rsa(*pKey), MBEDTLS_RSA_PKCS_V15, md_alg);
    }

    return md_alg;
}


