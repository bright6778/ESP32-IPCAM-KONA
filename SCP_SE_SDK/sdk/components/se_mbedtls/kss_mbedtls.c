#include "kona_kss_ftr_default.h"
#include "kona_kss_mbedtls_types.h"
#include "kona_kss_keyid_map.h"

#include "kona_kss_api.h"
#include "kona_kss_kose_types.h"
#include "ensure.h"
#include "mbedtls/base64.h"
#include "kss_mbedtls.h"



#include <inttypes.h>
//#include <nxLog_App.h>
#include <stdio.h>
#include <string.h>
//#include "sm_types.h"


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/pk.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define MAX_KEY_OBJ_COUNT KS_N_ENTIRES
#define MAX_FILE_NAME_SIZE 255
#define MAX_SHARED_SECRET_DERIVED_DATA 255
#define BEGIN_PRIVATE "-----BEGIN PRIVATE KEY-----\n"
#define END_PRIVATE "\n-----END PRIVATE KEY-----"
#define BEGIN_PUBLIC "-----BEGIN PUBLIC KEY-----\n"
#define END_PUBLIC "\n-----END PUBLIC KEY-----"

#define CIPHER_BLOCK_SIZE 16
#define DES_BLOCK_SIZE (MBEDTLS_KEY_LENGTH_DES / 8)


static const char *TAG = "kss_mbedtls.c";

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
                ret = mbedtls_ecp_group_load(&pEcpPrv->private_grp, MBEDTLS_ECP_DP_CURVE25519);
            }
            else if (keyBitLen == 448) {
                ret = mbedtls_ecp_group_load(&pEcpPrv->private_grp, MBEDTLS_ECP_DP_CURVE448);
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
            ret = mbedtls_mpi_read_binary(&pEcpPrv->private_d, data, dataLen);
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
                ret = mbedtls_ecp_group_load(&pEcpPub->private_grp, MBEDTLS_ECP_DP_CURVE25519);
            }
            else if (keyBitLen == 448) {
                ret = mbedtls_ecp_group_load(&pEcpPub->private_grp, MBEDTLS_ECP_DP_CURVE448);
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
            ret = mbedtls_mpi_read_binary(&pEcpPub->private_Q.private_X, data, dataLen);
#endif // Reverse Endianess

            (ret == 0) ? (retval = kStatus_KSS_Success) : (retval = kStatus_KSS_Fail);

            if (retval == kStatus_KSS_Success) {
                ret = mbedtls_mpi_lset(&pEcpPub->private_Q.private_Z, 1);
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

// only test
kss_status_t kss_mbedtls_key_object_init(kss_mbedtls_object_t *keyObject, kss_mbedtls_key_store_t *keyStore)
{
    kss_status_t retval = kStatus_KSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyStore);
    memset(keyObject, 0, sizeof(*keyObject));
    keyObject->keyStore = keyStore;
    retval              = kStatus_KSS_Success;
cleanup:
    return retval;
}

kss_status_t kss_mbedtls_key_object_allocate_handle(kss_mbedtls_object_t *keyObject,
    uint32_t keyId,
    kss_key_part_t key_part,
    kss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
    kss_status_t retval = kStatus_KSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyId != 0);
    ENSURE_OR_GO_CLEANUP(keyId != 0xFFFFFFFFu);

#ifdef EX_KSS_OBJID_TEST_START
    if (keyId < EX_KSS_OBJID_TEST_START) {
        return kStatus_KSS_Fail;
    }
    if (keyId > EX_KSS_OBJID_TEST_END) {
        return kStatus_KSS_Fail;
    }
#endif

    if (options != kKeyObject_Mode_Persistent && options != kKeyObject_Mode_Transient) {
        LOGE(TAG, "kss_mbedtls_key_object_allocate_handle option invalid 0x%ld", options);
        retval = kStatus_KSS_Fail;
        goto cleanup;
    }
    {
        /* to avoid error -Werror=type-limit */
        unsigned int uikey_part = ((unsigned int)key_part);
        if (uikey_part > UINT8_MAX) {
            LOGE(TAG, " Only objectType 8 bits wide supported");
            retval = kStatus_KSS_Fail;
            goto cleanup;
        }
    }
#if defined(MBEDTLS_FS_IO) && !AX_EMBEDDED
    if (options == kKeyObject_Mode_Persistent) {
        uint32_t i;
        kss_mbedtls_object_t **ks;
        ENSURE_OR_GO_CLEANUP(keyObject->keyStore);
        ENSURE_OR_GO_CLEANUP(keyObject->keyStore->max_object_count != 0);
        ENSURE_OR_GO_CLEANUP(keyByteLenMax < UINT16_MAX);
        retval = ks_common_update_fat(
            keyObject->keyStore->keystore_shadow, keyId, key_part, cipherType, 0, 0, (uint16_t)keyByteLenMax);
        ENSURE_OR_GO_CLEANUP(retval == kStatus_KSS_Success);
        ks     = keyObject->keyStore->objects;
        retval = kStatus_KSS_Fail;
        for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
            if (ks[i] == NULL) {
                ks[i]  = keyObject;
                retval = ks_mbedtls_key_object_create(keyObject, keyId, key_part, cipherType, keyByteLenMax, options);
                break;
            }
        }
    }
    else
#endif
    {
        retval = ks_mbedtls_key_object_create(keyObject, keyId, key_part, cipherType, keyByteLenMax, options);
    }
cleanup:
    return retval;
}

kss_status_t kss_mbedtls_key_store_context_init(kss_mbedtls_key_store_t *keyStore, kss_mbedtls_session_t *session)
{
    kss_status_t retval = kStatus_KSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyStore);
    ENSURE_OR_GO_CLEANUP(session);

    memset(keyStore, 0, sizeof(*keyStore));
    keyStore->session = session;
    retval            = kStatus_KSS_Success;
cleanup:
    return retval;
}

kss_status_t kss_mbedtls_key_store_allocate(kss_mbedtls_key_store_t *keyStore, uint32_t keyStoreId)
{
    kss_status_t retval = kStatus_KSS_Fail;
    AX_UNUSED_ARG(keyStoreId);
    ENSURE_OR_GO_CLEANUP(keyStore);
    ENSURE_OR_GO_CLEANUP(keyStore->session);

#if defined(MBEDTLS_FS_IO) && !AX_EMBEDDED
    /* This function is called once per session so keystore
    object and shadow objects Should be equal to Null */
    ENSURE_OR_GO_CLEANUP(keyStore->objects == NULL);
    ENSURE_OR_GO_CLEANUP(keyStore->keystore_shadow == NULL);

    keyStore->max_object_count = MAX_KEY_OBJ_COUNT;
    keyStore->objects = (kss_mbedtls_object_t **)malloc(MAX_KEY_OBJ_COUNT * sizeof(kss_mbedtls_object_t *));
    ENSURE_OR_GO_CLEANUP(keyStore->objects != NULL);
    memset(keyStore->objects, 0, (MAX_KEY_OBJ_COUNT * sizeof(kss_mbedtls_object_t *)));
    ks_sw_fat_allocate(&keyStore->keystore_shadow);
    if (keyStore->session->szRootPath != NULL) {
        ks_sw_fat_load(keyStore->session->szRootPath, keyStore->keystore_shadow);
    }
    retval = kStatus_KSS_Success;

#else
    retval = kStatus_KSS_Success;
#endif
cleanup:
    return retval;
}

kss_status_t kss_mbedtls_asymmetric_sign_digest(kss_mbedtls_asymmetric_t *context,
    const uint8_t *digest,
    size_t digestLen,
    uint8_t *signature,
    size_t *signatureLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_SW_ECC || KSSFTR_SW_RSA
    int ret                  = 1;
    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
    kss_mbedtls_session_t *pS;
    mbedtls_pk_context *pKey;

    //ENSURE_OR_GO_EXIT((context->keyObject->accessRights & kAccessPermission_KSS_Use));

    LOGD(TAG, "kss_mbedtls_asymmetric_sign_digest start");
    pS   = context->session;
    pKey = (mbedtls_pk_context *)context->keyObject->contents;

    md_alg = kss_mbedtls_set_padding_get_hash(context->algorithm, pKey);
    
    LOGD(TAG, "mbedtls_pk_sign start");
    LOGD(TAG, "md_alg : %d", md_alg);
    debug_showframe(TAG, digest, digestLen);
    
    ret = mbedtls_pk_sign(
        pKey, md_alg, digest, digestLen, signature, sizeof(signatureLen), signatureLen, mbedtls_ctr_drbg_random, pS->ctr_drbg);

    ENSURE_OR_GO_EXIT(ret == 0);

    retval = kStatus_KSS_Success;
exit:
#endif
    return retval;
}

kss_status_t kss_mbedtls_asymmetric_context_init(kss_mbedtls_asymmetric_t *context,
    kss_mbedtls_session_t *session,
    kss_mbedtls_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_SW_ECC || KSSFTR_SW_RSA
    ENSURE_OR_GO_CLEANUP(context);
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyObject->keyStore->session->subsystem == kType_KSS_mbedTLS);

    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;
    retval             = kStatus_KSS_Success;
cleanup:
#endif
    return retval;
}

kss_status_t ks_mbedtls_key_object_create(kss_mbedtls_object_t *keyObject,
    uint32_t keyId,
    kss_key_part_t keyPart,
    kss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t keyMode)
{
    size_t size         = 0;
    kss_status_t retval = kStatus_KSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyObject);

    keyObject->keyId              = keyId;
    keyObject->objectType         = keyPart;
    keyObject->cipherType         = cipherType;
    keyObject->contents_max_size  = keyByteLenMax;
    keyObject->contents_must_free = 1;
    keyObject->keyMode            = keyMode;
    /* Bitwise OR of all kss_access_permission. */
    keyObject->accessRights = kAccessPermission_KSS_All_Permission;
    switch (keyPart) {
    case kKSS_KeyPart_Default:
        size = keyByteLenMax;
        break;
#if KSSFTR_SW_ECC || KSSFTR_SW_RSA
    case kKSS_KeyPart_Pair:
    case kKSS_KeyPart_Private:
    case kKSS_KeyPart_Public:
        size = sizeof(mbedtls_pk_context);
        break;
#endif // KSSFTR_SW_ECC || KSSFTR_SW_RSA
    default:
        break;
    }
    if (size != 0) {
        keyObject->contents           = malloc(size);
        keyObject->contents_must_free = 1;
        ENSURE_OR_GO_CLEANUP(keyObject->contents);
        memset(keyObject->contents, 0, size);
        retval = kStatus_KSS_Success;
    }

cleanup:
    return retval;
}