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

#include "kona_kss_kose_types.h"
#include "kona_kss_api.h"
#include "kss_kose_rng.h"
#include "kss_kose_session.h"
#include "kss_kose_asymmetric.h"
#include "kss_kose_keyobj.h"
#include "kss_kose_keystore.h"
#include "kona_kss_ftr_default.h"
#include "kss_kose_rng.h"
#include "debug.h"

static const char *TAG = "kona_kss_api.c";

kss_status_t kss_session_create(kss_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData)
{
    AX_UNUSED_ARG(session);
    AX_UNUSED_ARG(application_id);
    AX_UNUSED_ARG(connection_type);
    AX_UNUSED_ARG(connectionData);

    if (kType_KSS_SecureElement == subsystem) {
        subsystem = kType_KSS_SecureElement;
        return kStatus_KSS_Success;
    }

    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_session_open(kss_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,    // se object id
    kss_connection_type_t connection_type,
    void *connectionData)
{
    if (kType_KSS_SecureElement == subsystem){
        kss_kose_session_t *kose_session = (kss_kose_session_t *)session;
        return kss_kose_session_open(kose_session, subsystem, application_id, connection_type, connectionData);
    }

    return kStatus_KSS_InvalidArgument;
}

void kss_session_close(kss_session_t *session)
{
    kss_kose_session_t *kose_session = (kss_kose_session_t *)session;
    kss_kose_session_close(kose_session);
}

/**************************************************************************************
 * asymmetric
 **************************************************************************************/

kss_status_t kss_asymmetric_context_init(kss_asymmetric_t *context,
    kss_session_t *session,
    kss_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_SESSION_TYPE_IS_KOSE(session)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        kss_kose_session_t *kose_session    = (kss_kose_session_t *)session;
        kss_kose_object_t *kose_keyObject   = (kss_kose_object_t *)keyObject;
        return kss_kose_asymmetric_context_init(kose_context, kose_session, kose_keyObject, algorithm, mode);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_asymmetric_encrypt(
    kss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        return kss_kose_asymmetric_encrypt(kose_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_asymmetric_decrypt(
    kss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        return kss_kose_asymmetric_decrypt(kose_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_asymmetric_sign_digest(
    kss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        return kss_kose_asymmetric_sign_digest(kose_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_asymmetric_verify_digest(
    kss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        return kss_kose_asymmetric_verify_digest(kose_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

void kss_asymmetric_context_free(kss_asymmetric_t *context)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        kss_kose_asymmetric_context_free(kose_context);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
}

/**************************************************************************************
 * key object
 **************************************************************************************/
kss_status_t kss_key_object_init(kss_object_t *keyObject, kss_key_store_t *keyStore)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_KEY_STORE_TYPE_IS_KOSE(keyStore)) {
        kss_kose_object_t *kose_keyObject   = (kss_kose_object_t *)keyObject;
        kss_kose_key_store_t *kose_keyStore = (kss_kose_key_store_t *)keyStore;
        KSS_ASSERT(sizeof(*kose_keyObject) <= sizeof(*keyObject));
        KSS_ASSERT(sizeof(*kose_keyStore) <= sizeof(*keyStore));
        return kss_kose_key_object_init(kose_keyObject, kose_keyStore);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_key_object_allocate_handle(kss_object_t *keyObject,
    uint32_t keyId,
    kss_key_part_t keyPart,
    kss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t acl,
    uint32_t options)
{
#if KSS_HAVE_APPLET_KOSE_IOT && KSSFTR_KOSE_KEY_SET
    if (KSS_OBJECT_TYPE_IS_KOSE(keyObject)) {
        kss_kose_object_t *kose_keyObject = (kss_kose_object_t *)keyObject;
        return kss_kose_key_object_allocate_handle(
            kose_keyObject, keyId, keyPart, cipherType, keyByteLenMax, acl, options);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_key_object_get_handle(kss_object_t *keyObject, uint32_t objectId)
{
#if KSS_HAVE_APPLET_KOSE_IOT && KSSFTR_KOSE_KEY_GET
    if (KSS_OBJECT_TYPE_IS_KOSE(keyObject)) {
        kss_kose_object_t *kose_keyObject = (kss_kose_object_t *)keyObject;
        return kss_kose_key_object_get_handle(kose_keyObject, objectId);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

void kss_key_object_free(kss_object_t *keyObject)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_OBJECT_TYPE_IS_KOSE(keyObject)) {
        kss_kose_object_t *kose_keyObject = (kss_kose_object_t *)keyObject;
        kss_kose_key_object_free(kose_keyObject);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
}

/**************************************************************************************
 * key store
 **************************************************************************************/

kss_status_t kss_key_store_context_init(kss_key_store_t *keyStore, kss_session_t *session)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_SESSION_TYPE_IS_KOSE(session)) {
        kss_kose_key_store_t *kose_keyStore = (kss_kose_key_store_t *)keyStore;
        kss_kose_session_t *kose_session    = (kss_kose_session_t *)session;
        KSS_ASSERT(sizeof(*kose_keyStore) <= sizeof(*keyStore));
        KSS_ASSERT(sizeof(*kose_session) <= sizeof(*session));
        return kss_kose_key_store_context_init(kose_keyStore, kose_session);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_key_store_allocate(kss_key_store_t *keyStore, uint32_t keyStoreId)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_KEY_STORE_TYPE_IS_KOSE(keyStore)) {
        kss_kose_key_store_t *kose_keyStore = (kss_kose_key_store_t *)keyStore;
        return kss_kose_key_store_allocate(kose_keyStore, keyStoreId);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_key_store_get_data(
    kss_key_store_t *keyStore, kss_object_t *keyObject, uint8_t *data, size_t *dataLen)
{
#if KSS_HAVE_APPLET_KOSE_IOT && KSSFTR_KOSE_KEY_GET
    if (KSS_KEY_STORE_TYPE_IS_KOSE(keyStore)) {
        kss_kose_key_store_t *kose_keyStore = (kss_kose_key_store_t *)keyStore;
        kss_kose_object_t *kose_keyObject   = (kss_kose_object_t *)keyObject;
        return kss_kose_key_store_get_data(kose_keyStore, kose_keyObject, data, dataLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_key_store_set_key(kss_key_store_t *keyStore,
kss_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen)
{
#if KSS_HAVE_APPLET_KOSE_IOT && KSSFTR_KOSE_KEY_SET
    if (KSS_KEY_STORE_TYPE_IS_KOSE(keyStore)) {
        kss_kose_key_store_t *kose_keyStore = (kss_kose_key_store_t *)keyStore;
        kss_kose_object_t *kose_keyObject   = (kss_kose_object_t *)keyObject;
        return kss_kose_key_store_set_key(
            kose_keyStore, kose_keyObject, data, dataLen, keyBitLen, options, optionsLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_key_store_set_keyfile(kss_key_store_t *keyStore,
    kss_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen)
{
#if KSS_HAVE_APPLET_KOSE_IOT && KSSFTR_KOSE_KEY_SET
    if (KSS_KEY_STORE_TYPE_IS_KOSE(keyStore)) {
        kss_kose_key_store_t *kose_keyStore = (kss_kose_key_store_t *)keyStore;
        kss_kose_object_t *kose_keyObject   = (kss_kose_object_t *)keyObject;
        return kss_kose_key_store_set_key(
            kose_keyStore, kose_keyObject, data, dataLen, keyBitLen, options, optionsLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}
/**************************************************************************************
 * random
 **************************************************************************************/

kss_status_t kss_rng_context_init(kss_rng_context_t *context, kss_session_t *session)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_SESSION_TYPE_IS_KOSE(session)) {
        kss_kose_rng_context_t *kose_context = (kss_kose_rng_context_t *)context;
        kss_kose_session_t *kose_session     = (kss_kose_session_t *)session;
        KSS_ASSERT(sizeof(*kose_context) <= sizeof(*context));
        KSS_ASSERT(sizeof(*kose_session) <= sizeof(*session));
        return kss_kose_rng_context_init(kose_context, kose_session);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_rng_get_random(kss_rng_context_t *context, uint8_t *random_data, size_t dataLen)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_RNG_CONTEXT_TYPE_IS_KOSE(context)) {
        kss_kose_rng_context_t *kose_context = (kss_kose_rng_context_t *)context;
        return kss_kose_rng_get_random(kose_context, random_data, dataLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_rng_context_free(kss_rng_context_t *context)
{
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_RNG_CONTEXT_TYPE_IS_KOSE(context)) {
        kss_kose_rng_context_t *kose_context = (kss_kose_rng_context_t *)context;
        return kss_kose_rng_context_free(kose_context);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
    return kStatus_KSS_InvalidArgument;
}

#ifdef __cplusplus
}
#endif