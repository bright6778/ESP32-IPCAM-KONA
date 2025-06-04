/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

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

    retval = kStatus_KSS_Success;
#endif // KSSFTR_KOSE_KEY_GET
    return retval;
}

#ifdef __cplusplus
}
#endif