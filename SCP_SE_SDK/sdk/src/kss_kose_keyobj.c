/** @file */
#ifdef __cplusplus
extern "C" {
#endif

#include "kona_kss_api.h"
#include "kona_kss_kose_types.h"
#include "kona_kss_ftr_default.h"
#include "kose_APDU_impl.h"
#include "kss_kose_keyobj.h"
#include "debug.h"

static const char *TAG = "kss_kose_keyobj.c";
/* ************************************************************************** */
/* Functions : kss_kose_keyobj                                                */
/* ************************************************************************** */

kss_status_t kss_kose_key_object_init(kss_kose_object_t *keyObject, kss_kose_key_store_t *keyStore)
{
    LOGD(TAG, "kss_kose_key_object_init");
    kss_status_t retval = kStatus_KSS_Success;
    if (keyObject == NULL) {
        return kStatus_KSS_Fail;
    }
    memset(keyObject, 0, sizeof(*keyObject));
    keyObject->keyStore = keyStore;

    return retval;
}

kss_status_t kss_kose_key_object_allocate_handle(kss_kose_object_t *keyObject,
    uint32_t keyId,
    kss_key_part_t keyPart,
    kss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
    LOGD(TAG, "kss_kose_key_object_allocate_handle");
    kss_status_t retval = kStatus_KSS_Success;
    smStatus_t status;
    KOSE_Result_t exists = kKOSE_Result_NA;
    keyObject->objectType = keyPart;
    keyObject->cipherType = cipherType;
    keyObject->keyId      = keyId;
    if (options == kKeyObject_Mode_Persistent) {
        keyObject->isPersistant = 1;
    }

    AX_UNUSED_ARG(keyByteLenMax);
/*
    status = Kose_API_CheckObjectExists(&keyObject->keyStore->session->s_ctx, keyId, &exists);
    if (status == SM_OK) {
        if (exists == kKOSE_Result_SUCCESS) {
            LOGD(TAG, "Object id 0x%X exists", keyId);
        }
    }
    else {
        LOGE(TAG, "Couldn't check if object id 0x%X exists", keyId);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            return kStatus_KSS_ApduThroughputError;
        }
        return kStatus_KSS_Fail;
    }
*/
    return retval;
}

kss_status_t kss_kose_key_object_get_handle(kss_kose_object_t *keyObject, uint32_t objectId)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_KOSE_KEY_GET
    KOSE_SecObjTyp_t retObjectType;
    uint8_t retTransientType;
    KOSE_ECCurve_t retCurveId;
    const KOSE_AttestationType_t attestationType = kKOSE_AttestationType_None;
    smStatus_t apiRetval                          = SM_NOT_OK;
    smStatus_t apduRetValue                       = SM_NOT_OK;

    keyObject->keyId = objectId;
    keyObject->cipherType = kKSS_CipherType_EC_NIST_P;
    keyObject->curve_id = kKOSE_ECCurve_NIST_P256;
    if(objectId >= ECC_KEYPAIR_PRIVATE_START && objectId <= ECC_KEYPAIR_PRIVATE_END)
    {
        keyObject->objectType = kKSS_KeyPart_Private;
    }
    else if(objectId >= ECC_KEYPAIR_PUBLIC_START && objectId <= ECC_KEYPAIR_PUBLIC_END)
    {
        keyObject->objectType = kKSS_KeyPart_Public;
    }
    
#if 0
        if (apiRetval == SM_OK) {
        keyObject->isPersistant = retTransientType;
        if (retObjectType >= kKOSE_SecObjTyp_EC_KEY_PAIR && retObjectType <= kKOSE_SecObjTyp_EC_PUB_KEY)
        {
            apiRetval = Kose_API_EC_CurveGetId(&keyObject->keyStore->session->s_ctx, keyId, &retCurveId);
            if (apiRetval == SM_OK) {
                keyObject->curve_id = retCurveId;
                if ((retCurveId == kKOSE_ECCurve_NIST_P256)
#if KSS_HAVE_EC_NIST_192
                    || (retCurveId == kKOSE_ECCurve_NIST_P192)
#endif
#if KSS_HAVE_EC_NIST_224
                    || (retCurveId == kKOSE_ECCurve_NIST_P224)
#endif
#if KSS_HAVE_EC_NIST_521
                    || (retCurveId == kKOSE_ECCurve_NIST_P521)
#endif
                    || (retCurveId == kKOSE_ECCurve_NIST_P384)) {
                    keyObject->cipherType = kKSS_CipherType_EC_NIST_P;
                }
#if KSS_HAVE_EC_BP
                else if ((retCurveId >= kKOSE_ECCurve_Brainpool160) && (retCurveId <= kKOSE_ECCurve_Brainpool512)) {
                    keyObject->cipherType = kKSS_CipherType_EC_BRAINPOOL;
                }
#endif
#if KSS_HAVE_EC_NIST_K
                else if ((retCurveId >= kKOSE_ECCurve_Secp160k1) && (retCurveId <= kKOSE_ECCurve_Secp256k1)) {
                    keyObject->cipherType = kKSS_CipherType_EC_NIST_K;
                }
#endif
#if KSS_HAVE_EC_ED
                else if (retCurveId == kKOSE_ECCurve_RESERVED_ID_ECC_ED_25519) {
                    keyObject->cipherType = kKSS_CipherType_EC_TWISTED_ED;
                }
#endif
#if KSS_HAVE_EC_MONT
                else if (retCurveId == kKOSE_ECCurve_RESERVED_ID_ECC_MONT_DH_25519) {
                    keyObject->cipherType = kKSS_CipherType_EC_MONTGOMERY;
                }
#endif
                else {
                    return kStatus_KSS_Fail;
                }
            }
            else {
                LOGE(TAG, "error in Kose_API_GetECCurveId");
                if (apiRetval == SM_ERR_APDU_THROUGHPUT) {
                    return kStatus_KSS_ApduThroughputError;
                }
                return kStatus_KSS_Fail;
            }
        }
#if KSSFTR_RSA && KSS_HAVE_RSA
        else if (retObjectType == kKOSE_SecObjTyp_RSA_KEY_PAIR_CRT) {
            keyObject->cipherType = kKSS_CipherType_RSA_CRT;
        }
        else if (retObjectType == kKOSE_SecObjTyp_RSA_PRIV_KEY_CRT) {
            keyObject->cipherType = kKSS_CipherType_RSA_CRT;
        }
        else if (retObjectType >= kKOSE_SecObjTyp_RSA_KEY_PAIR && retObjectType <= kKOSE_SecObjTyp_RSA_PUB_KEY) {
            keyObject->cipherType = kKSS_CipherType_RSA;
        }
#endif
        else if (retObjectType == kKOSE_SecObjTyp_AES_KEY) {
            keyObject->cipherType = kKSS_CipherType_AES;
        }
        else if (retObjectType == kKOSE_SecObjTyp_DES_KEY) {
            keyObject->cipherType = kKSS_CipherType_DES;
        }
        else if (retObjectType == kKOSE_SecObjTyp_BINARY_FILE) {
            keyObject->cipherType = kKSS_CipherType_Binary;
        }
        else if (retObjectType == kKOSE_SecObjTyp_UserID) {
            keyObject->cipherType = kKSS_CipherType_UserID;
        }
        else if (retObjectType == kKOSE_SecObjTyp_COUNTER) {
            keyObject->cipherType = kKSS_CipherType_Count;
        }
        else if (retObjectType == kKOSE_SecObjTyp_PCR) {
            keyObject->cipherType = kKSS_CipherType_PCR;
        }
        else if (retObjectType == kKOSE_SecObjTyp_HMAC_KEY) {
            keyObject->cipherType = kKSS_CipherType_HMAC;
        }
        else {
            return kStatus_KSS_Fail;
        }

        switch (retObjectType) {
        case kKOSE_SecObjTyp_EC_KEY_PAIR:
#if KSS_HAVE_RSA
        case kKOSE_SecObjTyp_RSA_KEY_PAIR:
        case kKOSE_SecObjTyp_RSA_KEY_PAIR_CRT:
#endif
#if KSS_HAVE_KOSE_VER_GTE_07_02
        case kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P192:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P224:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P256:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P384:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P521:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool160:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool192:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool224:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool256:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool320:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool384:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool512:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Secp160k1:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Secp192k1:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Secp224k1:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_Secp256k1:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_BN_P256:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_ED25519:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_MONT_DH_25519:
        case kKOSE_SecObjTyp_EC_KEY_PAIR_MONT_DH_448:
#endif
            keyObject->objectType = kKSS_KeyPart_Pair;
            break;

        case kKOSE_SecObjTyp_EC_PUB_KEY:
        case kKOSE_SecObjTyp_RSA_PUB_KEY:
#if KSS_HAVE_KOSE_VER_GTE_07_02
        case kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P192:
        case kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P224:
        case kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P256:
        case kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P384:
        case kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P521:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool160:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool192:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool224:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool256:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool320:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool384:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool512:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Secp160k1:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Secp192k1:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Secp224k1:
        case kKOSE_SecObjTyp_EC_PUB_KEY_Secp256k1:
        case kKOSE_SecObjTyp_EC_PUB_KEY_BN_P256:
        case kKOSE_SecObjTyp_EC_PUB_KEY_ED25519:
        case kKOSE_SecObjTyp_EC_PUB_KEY_MONT_DH_25519:
        case kKOSE_SecObjTyp_EC_PUB_KEY_MONT_DH_448:
#endif
            keyObject->objectType = kKSS_KeyPart_Public;
            break;

#if KSS_HAVE_KOSE_VER_GTE_07_02
        case kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P192:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P224:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P256:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P384:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P521:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool160:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool192:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool224:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool256:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool320:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool384:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool512:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Secp160k1:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Secp192k1:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Secp224k1:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_Secp256k1:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_BN_P256:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_ED25519:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_MONT_DH_25519:
        case kKOSE_SecObjTyp_EC_PRIV_KEY_MONT_DH_448:
            keyObject->objectType = kKSS_KeyPart_Private;
            break;
#endif

        case kKOSE_SecObjTyp_BINARY_FILE:
        case kKOSE_SecObjTyp_PCR:
        case kKOSE_SecObjTyp_AES_KEY:
        case kKOSE_SecObjTyp_DES_KEY:
        case kKOSE_SecObjTyp_HMAC_KEY:
        case kKOSE_SecObjTyp_COUNTER:
        case kKOSE_SecObjTyp_UserID:
            keyObject->objectType = kKSS_KeyPart_Default;
            break;
        default:
            return kStatus_KSS_Fail;
        }
    }
    else {
        LOGI(TAG, "Error in Kose_API_ReadType. Further use of object may fail");
        if (apiRetval == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
        }
        else {
            retval = kStatus_KSS_Success;
        }
        return retval;
    }
#endif
    retval = kStatus_KSS_Success;
#endif // KSSFTR_KOSE_KEY_GET
    return retval;
}

#ifdef __cplusplus
}
#endif