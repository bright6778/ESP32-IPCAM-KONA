/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file */

#ifndef FSL_KSS_KOSE_APIS_H
#define FSL_KSS_KOSE_APIS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(KSS_USE_FTR_FILE)
#include "kona_kss_ftr.h"
#else
#include "kona_kss_ftr_default.h"
#endif

#if KSS_HAVE_APPLET_KOSE_IOT
#include <kona_kss_kose_types.h>

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */
/**
 * @addtogroup kss_kose_session
 * @{
 */
/** @copydoc kss_session_create
 *
 */
kss_status_t kss_kose_session_create(kss_kose_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData);

/** @copydoc kss_session_open
 *
 */
kss_status_t kss_kose_session_open(kss_kose_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData);

/** @copydoc kss_session_prop_get_u32
 *
 */
kss_status_t kss_kose_session_prop_get_u32(kss_kose_session_t *session, uint32_t property, uint32_t *pValue);

/** @copydoc kss_session_prop_get_au8
 *
 */
kss_status_t kss_kose_session_prop_get_au8(
    kss_kose_session_t *session, uint32_t property, uint8_t *pValue, size_t *pValueLen);

/** @copydoc kss_session_close
 *
 */
void kss_kose_session_close(kss_kose_session_t *session);

/** @copydoc kss_session_delete
 *
 */
void kss_kose_session_delete(kss_kose_session_t *session);

/*! @} */ /* end of : kss_kose_session */

/**
 * @addtogroup kss_kose_keyobj
 * @{
 */
/** @copydoc kss_key_object_init
 *
 */
kss_status_t kss_kose_key_object_init(kss_kose_object_t *keyObject, kss_kose_key_store_t *keyStore);

/** @copydoc kss_key_object_allocate_handle
 *
 * On SE050, the memory get reserved only when the actual object is created and
 * hence there is no memory reservation happening in this API call.  but
 * internally it checks if the object already exists or not . if the object is
 * already existing it returns a failure.
 *
 */
kss_status_t kss_kose_key_object_allocate_handle(kss_kose_object_t *keyObject,
    uint32_t keyId,
    kss_key_part_t keyPart,
    kss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

/** @copydoc kss_key_object_get_handle
 *
 * On KOSE, this API uses @ref Kose_API_ReadType and fetches
 * parameters of the API.
 *
 */
kss_status_t kss_kose_key_object_get_handle(kss_kose_object_t *keyObject, uint32_t keyId);

/** Not Available for KOSE
 *
 */
kss_status_t kss_kose_key_object_set_user(kss_kose_object_t *keyObject, uint32_t user, uint32_t options);

/** @copydoc kss_key_object_set_purpose
 *
 */
kss_status_t kss_kose_key_object_set_purpose(kss_kose_object_t *keyObject, kss_mode_t purpose, uint32_t options);

/** Not Available for KOSE
 *
 */
kss_status_t kss_kose_key_object_set_access(kss_kose_object_t *keyObject, uint32_t access, uint32_t options);

/** Not Available for KOSE
 *
 */
kss_status_t kss_kose_key_object_set_eccgfp_group(kss_kose_object_t *keyObject, kss_eccgfp_group_t *group);

/** Not Available for KOSE
 *
 */
kss_status_t kss_kose_key_object_get_user(kss_kose_object_t *keyObject, uint32_t *user);

/** Not Available for KOSE
 *
 */
kss_status_t kss_kose_key_object_get_purpose(kss_kose_object_t *keyObject, kss_mode_t *purpose);

/** Not Available for KOSE
 *
 */
kss_status_t kss_kose_key_object_get_access(kss_kose_object_t *keyObject, uint32_t *access);

/** @copydoc kss_key_object_free
 *
 * On SE050, this has no impact on physical Key Object.
 */
void kss_kose_key_object_free(kss_kose_object_t *keyObject);

/*! @} */ /* end of : kss_kose_keyobj */

/**
 * @addtogroup kss_kose_keyderive
 * @{
 */
/** @copydoc kss_derive_key_context_init
 *
 */
kss_status_t kss_kose_derive_key_context_init(kss_kose_derive_key_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode);

/** @copydoc kss_derive_key_go
 *
 */
kss_status_t kss_kose_derive_key_go(kss_kose_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    kss_kose_object_t *derivedKeyObject,
    uint16_t deriveDataLen,
    uint8_t *hkdfOutput,
    size_t *hkdfOutputLen);

/** @copydoc kss_derive_key_one_go
 *
 */
kss_status_t kss_kose_derive_key_one_go(kss_kose_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    kss_kose_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/** @copydoc kss_derive_key_sobj_one_go
*
*/
kss_status_t kss_kose_derive_key_sobj_one_go(kss_kose_derive_key_t *context,
    kss_kose_object_t *saltKeyObject,
    const uint8_t *info,
    size_t infoLen,
    kss_kose_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/** @copydoc kss_derive_key_dh
 *
 */
kss_status_t kss_kose_derive_key_dh(
    kss_kose_derive_key_t *context, kss_kose_object_t *otherPartyKeyObject, kss_kose_object_t *derivedKeyObject);

/** @copydoc kss_derive_key_context_free
 *
 */
void kss_kose_derive_key_context_free(kss_kose_derive_key_t *context);

/*! @} */ /* end of : kss_kose_keyderive */

/**
 * @addtogroup kss_kose_keystore
 * @{
 */
/** @copydoc kss_key_store_context_init
 *
 */
kss_status_t kss_kose_key_store_context_init(kss_kose_key_store_t *keyStore, kss_kose_session_t *session);

/** @copydoc kss_key_store_allocate
 *
 * This API does not do anything special on KOSE.
 */
kss_status_t kss_kose_key_store_allocate(kss_kose_key_store_t *keyStore, uint32_t keyStoreId);

/** @copydoc kss_key_store_save
 *
 * This API does not do anything special on KOSE.
 */
kss_status_t kss_kose_key_store_save(kss_kose_key_store_t *keyStore);

/** @copydoc kss_key_store_load
 *
 * This API does not do anything special on KOSE.
 */
kss_status_t kss_kose_key_store_load(kss_kose_key_store_t *keyStore);

/** @copydoc kss_key_store_set_key
 *
 */
kss_status_t kss_kose_key_store_set_key(kss_kose_key_store_t *keyStore,
    kss_kose_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen);

/** @copydoc kss_key_store_generate_key
 *
 */
kss_status_t kss_kose_key_store_generate_key(
    kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject, size_t keyBitLen, void *options);

/** @copydoc kss_key_store_get_key
 *
 */
kss_status_t kss_kose_key_store_get_key(
    kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen);

/** @copydoc kss_key_store_open_key
 *
 * In KOSE, these keys can be used as KEK encryption key
 *
 * If ``keyObject`` == NULL, then subsequent key injection does not use any KEK.
 *
 * @return     The kss status.
 */
kss_status_t kss_kose_key_store_open_key(kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject);

/** Not available for KOSE
 *
 */
kss_status_t kss_kose_key_store_freeze_key(kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject);

/** @copydoc kss_key_store_erase_key
 *
 */
kss_status_t kss_kose_key_store_erase_key(kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject);

/** @copydoc kss_key_store_context_free
 *
 */
void kss_kose_key_store_context_free(kss_kose_key_store_t *keyStore);

/** Export Key from SE050 to host
 *
 * Only Transient keys can be exported.
 */
kss_status_t kss_kose_key_store_export_key(
    kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject, uint8_t *key, size_t *keylen);

/** Re Import previously exported KOSE key from host to the KOSE
 *
 * Only Transient keys can be imported.
 */
kss_status_t kss_kose_key_store_import_key(
    kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject, uint8_t *key, size_t keylen);

/*! @} */ /* end of : kss_kose_keystore */

/**
 * @addtogroup kss_kose_asym
 * @{
 */
/** @copydoc kss_asymmetric_context_init
 *
 */
kss_status_t kss_kose_asymmetric_context_init(kss_kose_asymmetric_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode);

/** @copydoc kss_asymmetric_encrypt
 *
 */
kss_status_t kss_kose_asymmetric_encrypt(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc kss_asymmetric_decrypt
 *
 */
kss_status_t kss_kose_asymmetric_decrypt(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc kss_asymmetric_sign_digest
 *
 */
kss_status_t kss_kose_asymmetric_sign_digest(
    kss_kose_asymmetric_t *context, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc kss_asymmetric_verify_digest
 *
 */
kss_status_t kss_kose_asymmetric_verify_digest(kss_kose_asymmetric_t *context,
    const uint8_t *digest,
    size_t digestLen,
    const uint8_t *signature,
    size_t signatureLen);

/** @copydoc kss_asymmetric_context_free
 *
 */
void kss_kose_asymmetric_context_free(kss_kose_asymmetric_t *context);

/*! @} */ /* end of : kss_kose_asym */

/**
 * @addtogroup kss_kose_symm
 * @{
 */
/** @copydoc kss_symmetric_context_init
 *
 */
kss_status_t kss_kose_symmetric_context_init(kss_kose_symmetric_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode);

/** @copydoc kss_cipher_one_go
 *
 */
kss_status_t kss_kose_cipher_one_go(kss_kose_symmetric_t *context,
    uint8_t *iv,
    size_t ivLen,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t dataLen);

/** @copydoc kss_cipher_one_go_v2
 *
 */
kss_status_t kss_kose_cipher_one_go_v2(kss_kose_symmetric_t *context,
    uint8_t *iv,
    size_t ivLen,
    const uint8_t *srcData,
    const size_t srcLen,
    uint8_t *destData,
    size_t *pDataLen);

/** @copydoc kss_cipher_init
 *
 */
kss_status_t kss_kose_cipher_init(kss_kose_symmetric_t *context, uint8_t *iv, size_t ivLen);

/** @copydoc kss_cipher_update
 *
 */
kss_status_t kss_kose_cipher_update(
    kss_kose_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc kss_cipher_finish
 *
 */
kss_status_t kss_kose_cipher_finish(
    kss_kose_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc kss_cipher_crypt_ctr
 *
 */
kss_status_t kss_kose_cipher_crypt_ctr(kss_kose_symmetric_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *initialCounter,
    uint8_t *lastEncryptedCounter,
    size_t *szLeft);

/** @copydoc kss_symmetric_context_free
 *
 */
void kss_kose_symmetric_context_free(kss_kose_symmetric_t *context);

/*! @} */ /* end of : kss_kose_symm */

/**
 * @addtogroup kss_kose_aead
 * @{
 */
/** @copydoc kss_aead_context_init
 *
 */
kss_status_t kss_kose_aead_context_init(kss_kose_aead_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode);

/** @copydoc kss_aead_one_go
 *
 */
kss_status_t kss_kose_aead_one_go(kss_kose_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);

/** @copydoc kss_aead_init
 *
 */
kss_status_t kss_kose_aead_init(
    kss_kose_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);

/** @copydoc kss_aead_update_aad
 *
 */
kss_status_t kss_kose_aead_update_aad(kss_kose_aead_t *context, const uint8_t *aadData, size_t aadDataLen);

/** @copydoc kss_aead_update
 *
 */
kss_status_t kss_kose_aead_update(
    kss_kose_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc kss_aead_finish
 *
 */
kss_status_t kss_kose_aead_finish(kss_kose_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen);

/** @copydoc kss_aead_context_free
 *
 */
void kss_kose_aead_context_free(kss_kose_aead_t *context);

/*! @} */ /* end of : kss_kose_aead */

/**
 * @addtogroup kss_kose_mac
 * @{
 */
/** @copydoc kss_mac_context_init
 *
 */
kss_status_t kss_kose_mac_context_init(kss_kose_mac_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode);

/** @copydoc kss_mac_one_go
 *
 */
kss_status_t kss_kose_mac_one_go(
    kss_kose_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen);

/** @copydoc kss_mac_init
 *
 */
kss_status_t kss_kose_mac_init(kss_kose_mac_t *context);

/** @copydoc kss_mac_update
 *
 */
kss_status_t kss_kose_mac_update(kss_kose_mac_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc kss_mac_finish
 *
 */
kss_status_t kss_kose_mac_finish(kss_kose_mac_t *context, uint8_t *mac, size_t *macLen);

/** @copydoc kss_mac_context_free
 *
 */
void kss_kose_mac_context_free(kss_kose_mac_t *context);

/*! @} */ /* end of : kss_kose_mac */

/**
 * @addtogroup kss_kose_md
 * @{
 */
/** @copydoc kss_digest_context_init
 *
 */
kss_status_t kss_kose_digest_context_init(
    kss_kose_digest_t *context, kss_kose_session_t *session, kss_algorithm_t algorithm, kss_mode_t mode);

/** @copydoc kss_digest_one_go
 *
 */
kss_status_t kss_kose_digest_one_go(
    kss_kose_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

/** @copydoc kss_digest_init
 *
 */
kss_status_t kss_kose_digest_init(kss_kose_digest_t *context);

/** @copydoc kss_digest_update
 *
 */
kss_status_t kss_kose_digest_update(kss_kose_digest_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc kss_digest_finish
 *
 */
kss_status_t kss_kose_digest_finish(kss_kose_digest_t *context, uint8_t *digest, size_t *digestLen);

/** @copydoc kss_digest_context_free
 *
 */
void kss_kose_digest_context_free(kss_kose_digest_t *context);

/*! @} */ /* end of : kss_kose_md */

/**
 * @addtogroup kss_kose_rng
 * @{
 */
/** @copydoc kss_rng_context_init
 *
 */
kss_status_t kss_kose_rng_context_init(kss_kose_rng_context_t *context, kss_kose_session_t *session);

/** @copydoc kss_rng_get_random
 *
 */
kss_status_t kss_kose_rng_get_random(kss_kose_rng_context_t *context, uint8_t *random_data, size_t dataLen);

/** @copydoc kss_rng_context_free
 *
 */
kss_status_t kss_kose_rng_context_free(kss_kose_rng_context_t *context);

/*! @} */ /* end of : kss_kose_rng */

/**
* @addtogroup kss_kose_tunnel
* @{
*/
/** @copydoc kss_tunnel_context_init
 *
 */
kss_status_t kss_kose_tunnel_context_init(kss_kose_tunnel_context_t *context, kss_kose_session_t *session);

/** @copydoc kss_tunnel_context_free
*
*/
void kss_kose_tunnel_context_free(kss_kose_tunnel_context_t *context);

/*! @} */ /* end of : kss_kose_tunnel */

/** Refreshes the KOSE session
*
*/
kss_status_t kss_kose_refresh_session(kss_kose_session_t *session, void *connectionData);

/**
 * @addtogroup kss_kose_tunnel
 * @{
 */

/** @copydoc kss_tunnel_context_init
 *
 */
kss_status_t kss_kose_tunnel_context_init(kss_kose_tunnel_context_t *context, kss_kose_session_t *session);

/** @copydoc kss_tunnel_t
 *
 */
kss_status_t kss_kose_tunnel(kss_kose_tunnel_context_t *context,
    uint8_t *data,
    size_t dataLen,
    kss_kose_object_t *keyObjects,
    uint32_t keyObjectCount,
    uint32_t tunnelType);

/** @copydoc kss_tunnel_context_free
 *
 */
void kss_kose_tunnel_context_free(kss_kose_tunnel_context_t *context);

/*! @} */ /* end of : kss_kose_tunnel */

/**
 * @addtogroup kose_other
 * @{
 */

/** Set features of the Applet.
 *
 * See @ref Kose_API_SetAppletFeatures
 */
kss_status_t kss_kose_set_feature(
    kss_kose_session_t *session, KOSE_Applet_Feature_t feature, KOSE_Applet_Feature_Disable_t disable_features);

/*! @} */

/** Gets the KOSE Digest Mode correspanding to the provided sha algorithm
*
*/
KOSE_DigestMode_t kose_get_sha_algo(kss_algorithm_t algorithm);

#if KSSFTR_KOSE_ECC
/** Creates a key store entry for specified curve
*/
kss_status_t kss_kose_key_store_create_curve(KoseSession_t *pSession, uint32_t curve_id);
#endif

/* clang-format off */
#   if (KSS_HAVE_KSS == 1)
        /* Direct Call : session */
#       define kss_session_create(session,subsystem,application_id,connection_type,connectionData) \
            kss_kose_session_create(((kss_kose_session_t * ) session),(subsystem),(application_id),(connection_type),(connectionData))
#       define kss_session_open(session,subsystem,application_id,connection_type,connectionData) \
            kss_kose_session_open(((kss_kose_session_t * ) session),(subsystem),(application_id),(connection_type),(connectionData))
#       define kss_session_prop_get_u32(session,property,pValue) \
            kss_kose_session_prop_get_u32(((kss_kose_session_t * ) session),(property),(pValue))
#       define kss_session_prop_get_au8(session,property,pValue,pValueLen) \
            kss_kose_session_prop_get_au8(((kss_kose_session_t * ) session),(property),(pValue),(pValueLen))
#       define kss_session_close(session) \
            kss_kose_session_close(((kss_kose_session_t * ) session))
#       define kss_session_delete(session) \
            kss_kose_session_delete(((kss_kose_session_t * ) session))
        /* Direct Call : keyobj */
#       define kss_key_object_init(keyObject,keyStore) \
            kss_kose_key_object_init(((kss_kose_object_t * ) keyObject),((kss_kose_key_store_t * ) keyStore))
#       define kss_key_object_allocate_handle(keyObject,keyId,keyPart,cipherType,keyByteLenMax,options) \
            kss_kose_key_object_allocate_handle(((kss_kose_object_t * ) keyObject),(keyId),(keyPart),(cipherType),(keyByteLenMax),(options))
#       define kss_key_object_get_handle(keyObject,keyId) \
            kss_kose_key_object_get_handle(((kss_kose_object_t * ) keyObject),(keyId))
#       define kss_key_object_set_user(keyObject,user,options) \
            kss_kose_key_object_set_user(((kss_kose_object_t * ) keyObject),(user),(options))
#       define kss_key_object_set_purpose(keyObject,purpose,options) \
            kss_kose_key_object_set_purpose(((kss_kose_object_t * ) keyObject),(purpose),(options))
#       define kss_key_object_set_access(keyObject,access,options) \
            kss_kose_key_object_set_access(((kss_kose_object_t * ) keyObject),(access),(options))
#       define kss_key_object_set_eccgfp_group(keyObject,group) \
            kss_kose_key_object_set_eccgfp_group(((kss_kose_object_t * ) keyObject),(group))
#       define kss_key_object_get_user(keyObject,user) \
            kss_kose_key_object_get_user(((kss_kose_object_t * ) keyObject),(user))
#       define kss_key_object_get_purpose(keyObject,purpose) \
            kss_kose_key_object_get_purpose(((kss_kose_object_t * ) keyObject),(purpose))
#       define kss_key_object_get_access(keyObject,access) \
            kss_kose_key_object_get_access(((kss_kose_object_t * ) keyObject),(access))
#       define kss_key_object_free(keyObject) \
            kss_kose_key_object_free(((kss_kose_object_t * ) keyObject))
        /* Direct Call : keyderive */
#       define kss_derive_key_context_init(context,session,keyObject,algorithm,mode) \
            kss_kose_derive_key_context_init(((kss_kose_derive_key_t * ) context),((kss_kose_session_t * ) session),((kss_kose_object_t * ) keyObject),(algorithm),(mode))
#       define kss_derive_key_go(context,saltData,saltLen,info,infoLen,derivedKeyObject,deriveDataLen,hkdfOutput,hkdfOutputLen) \
            kss_kose_derive_key_go(((kss_kose_derive_key_t * ) context),(saltData),(saltLen),(info),(infoLen),((kss_kose_object_t * ) derivedKeyObject),(deriveDataLen),(hkdfOutput),(hkdfOutputLen))
#       define kss_derive_key_dh(context,otherPartyKeyObject,derivedKeyObject) \
            kss_kose_derive_key_dh(((kss_kose_derive_key_t * ) context),((kss_kose_object_t * ) otherPartyKeyObject),((kss_kose_object_t * ) derivedKeyObject))
#       define kss_derive_key_context_free(context) \
            kss_kose_derive_key_context_free(((kss_kose_derive_key_t * ) context))
        /* Direct Call : keystore */
#       define kss_key_store_context_init(keyStore,session) \
            kss_kose_key_store_context_init(((kss_kose_key_store_t * ) keyStore),((kss_kose_session_t * ) session))
#       define kss_key_store_allocate(keyStore,keyStoreId) \
            kss_kose_key_store_allocate(((kss_kose_key_store_t * ) keyStore),(keyStoreId))
#       define kss_key_store_save(keyStore) \
            kss_kose_key_store_save(((kss_kose_key_store_t * ) keyStore))
#       define kss_key_store_load(keyStore) \
            kss_kose_key_store_load(((kss_kose_key_store_t * ) keyStore))
#       define kss_key_store_set_key(keyStore,keyObject,data,dataLen,keyBitLen,options,optionsLen) \
            kss_kose_key_store_set_key(((kss_kose_key_store_t * ) keyStore),((kss_kose_object_t * ) keyObject),(data),(dataLen),(keyBitLen),(options),(optionsLen))
#       define kss_key_store_generate_key(keyStore,keyObject,keyBitLen,options) \
            kss_kose_key_store_generate_key(((kss_kose_key_store_t * ) keyStore),((kss_kose_object_t * ) keyObject),(keyBitLen),(options))
#       define kss_key_store_get_key(keyStore,keyObject,data,dataLen,pKeyBitLen) \
            kss_kose_key_store_get_key(((kss_kose_key_store_t * ) keyStore),((kss_kose_object_t * ) keyObject),(data),(dataLen),(pKeyBitLen))
#       define kss_key_store_open_key(keyStore,keyObject) \
            kss_kose_key_store_open_key(((kss_kose_key_store_t * ) keyStore),((kss_kose_object_t * ) keyObject))
#       define kss_key_store_freeze_key(keyStore,keyObject) \
            kss_kose_key_store_freeze_key(((kss_kose_key_store_t * ) keyStore),((kss_kose_object_t * ) keyObject))
#       define kss_key_store_erase_key(keyStore,keyObject) \
            kss_kose_key_store_erase_key(((kss_kose_key_store_t * ) keyStore),((kss_kose_object_t * ) keyObject))
#       define kss_key_store_context_free(keyStore) \
            kss_kose_key_store_context_free(((kss_kose_key_store_t * ) keyStore))
        /* Direct Call : asym */
#       define kss_asymmetric_context_init(context,session,keyObject,algorithm,mode) \
            kss_kose_asymmetric_context_init(((kss_kose_asymmetric_t * ) context),((kss_kose_session_t * ) session),((kss_kose_object_t * ) keyObject),(algorithm),(mode))
#       define kss_asymmetric_encrypt(context,srcData,srcLen,destData,destLen) \
            kss_kose_asymmetric_encrypt(((kss_kose_asymmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define kss_asymmetric_decrypt(context,srcData,srcLen,destData,destLen) \
            kss_kose_asymmetric_decrypt(((kss_kose_asymmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define kss_asymmetric_sign_digest(context,digest,digestLen,signature,signatureLen) \
            kss_kose_asymmetric_sign_digest(((kss_kose_asymmetric_t * ) context),(digest),(digestLen),(signature),(signatureLen))
#       define kss_asymmetric_verify_digest(context,digest,digestLen,signature,signatureLen) \
            kss_kose_asymmetric_verify_digest(((kss_kose_asymmetric_t * ) context),(digest),(digestLen),(signature),(signatureLen))
#       define kss_asymmetric_context_free(context) \
            kss_kose_asymmetric_context_free(((kss_kose_asymmetric_t * ) context))
        /* Direct Call : symm */
#       define kss_symmetric_context_init(context,session,keyObject,algorithm,mode) \
            kss_kose_symmetric_context_init(((kss_kose_symmetric_t * ) context),((kss_kose_session_t * ) session),((kss_kose_object_t * ) keyObject),(algorithm),(mode))
#       define kss_cipher_one_go(context,iv,ivLen,srcData,destData,dataLen) \
            kss_kose_cipher_one_go(((kss_kose_symmetric_t * ) context),(iv),(ivLen),(srcData),(destData),(dataLen))
#       define kss_cipher_one_go_v2(context,iv,ivLen,srcData,srcLen,destData,pDataLen) \
            kss_kose_cipher_one_go_v2(((kss_kose_symmetric_t * ) context),(iv),(ivLen),(srcData),(srcLen),(destData),(pDataLen))
#       define kss_cipher_init(context,iv,ivLen) \
            kss_kose_cipher_init(((kss_kose_symmetric_t * ) context),(iv),(ivLen))
#       define kss_cipher_update(context,srcData,srcLen,destData,destLen) \
            kss_kose_cipher_update(((kss_kose_symmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define kss_cipher_finish(context,srcData,srcLen,destData,destLen) \
            kss_kose_cipher_finish(((kss_kose_symmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define kss_cipher_crypt_ctr(context,srcData,destData,size,initialCounter,lastEncryptedCounter,szLeft) \
            kss_kose_cipher_crypt_ctr(((kss_kose_symmetric_t * ) context),(srcData),(destData),(size),(initialCounter),(lastEncryptedCounter),(szLeft))
#       define kss_symmetric_context_free(context) \
            kss_kose_symmetric_context_free(((kss_kose_symmetric_t * ) context))
        /* Direct Call : aead */
#       define kss_aead_context_init(context,session,keyObject,algorithm,mode) \
            kss_kose_aead_context_init(((kss_kose_aead_t * ) context),((kss_kose_session_t * ) session),((kss_kose_object_t * ) keyObject),(algorithm),(mode))
#       define kss_aead_one_go(context,srcData,destData,size,nonce,nonceLen,aad,aadLen,tag,tagLen) \
            kss_kose_aead_one_go(((kss_kose_aead_t * ) context),(srcData),(destData),(size),(nonce),(nonceLen),(aad),(aadLen),(tag),(tagLen))
#       define kss_aead_init(context,nonce,nonceLen,tagLen,aadLen,payloadLen) \
            kss_kose_aead_init(((kss_kose_aead_t * ) context),(nonce),(nonceLen),(tagLen),(aadLen),(payloadLen))
#       define kss_aead_update_aad(context,aadData,aadDataLen) \
            kss_kose_aead_update_aad(((kss_kose_aead_t * ) context),(aadData),(aadDataLen))
#       define kss_aead_update(context,srcData,srcLen,destData,destLen) \
            kss_kose_aead_update(((kss_kose_aead_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define kss_aead_finish(context,srcData,srcLen,destData,destLen,tag,tagLen) \
            kss_kose_aead_finish(((kss_kose_aead_t * ) context),(srcData),(srcLen),(destData),(destLen),(tag),(tagLen))
#       define kss_aead_context_free(context) \
            kss_kose_aead_context_free(((kss_kose_aead_t * ) context))
        /* Direct Call : mac */
#       define kss_mac_context_init(context,session,keyObject,algorithm,mode) \
            kss_kose_mac_context_init(((kss_kose_mac_t * ) context),((kss_kose_session_t * ) session),((kss_kose_object_t * ) keyObject),(algorithm),(mode))
#       define kss_mac_one_go(context,message,messageLen,mac,macLen) \
            kss_kose_mac_one_go(((kss_kose_mac_t * ) context),(message),(messageLen),(mac),(macLen))
#       define kss_mac_init(context) \
            kss_kose_mac_init(((kss_kose_mac_t * ) context))
#       define kss_mac_update(context,message,messageLen) \
            kss_kose_mac_update(((kss_kose_mac_t * ) context),(message),(messageLen))
#       define kss_mac_finish(context,mac,macLen) \
            kss_kose_mac_finish(((kss_kose_mac_t * ) context),(mac),(macLen))
#       define kss_mac_context_free(context) \
            kss_kose_mac_context_free(((kss_kose_mac_t * ) context))
        /* Direct Call : md */
#       define kss_digest_context_init(context,session,algorithm,mode) \
            kss_kose_digest_context_init(((kss_kose_digest_t * ) context),((kss_kose_session_t * ) session),(algorithm),(mode))
#       define kss_digest_one_go(context,message,messageLen,digest,digestLen) \
            kss_kose_digest_one_go(((kss_kose_digest_t * ) context),(message),(messageLen),(digest),(digestLen))
#       define kss_digest_init(context) \
            kss_kose_digest_init(((kss_kose_digest_t * ) context))
#       define kss_digest_update(context,message,messageLen) \
            kss_kose_digest_update(((kss_kose_digest_t * ) context),(message),(messageLen))
#       define kss_digest_finish(context,digest,digestLen) \
            kss_kose_digest_finish(((kss_kose_digest_t * ) context),(digest),(digestLen))
#       define kss_digest_context_free(context) \
            kss_kose_digest_context_free(((kss_kose_digest_t * ) context))
        /* Direct Call : rng */
#       define kss_rng_context_init(context,session) \
            kss_kose_rng_context_init(((kss_kose_rng_context_t * ) context),((kss_kose_session_t * ) session))
#       define kss_rng_get_random(context,random_data,dataLen) \
            kss_kose_rng_get_random(((kss_kose_rng_context_t * ) context),(random_data),(dataLen))
#       define kss_rng_context_free(context) \
            kss_kose_rng_context_free(((kss_kose_rng_context_t * ) context))
        /* Direct Call : tunnel */
#       define kss_tunnel_context_init(context,session) \
            kss_kose_tunnel_context_init(((kss_kose_tunnel_context_t * ) context),((kss_kose_session_t * ) session))
#       define kss_tunnel(context,data,dataLen,keyObjects,keyObjectCount,tunnelType) \
            kss_kose_tunnel(((kss_kose_tunnel_context_t * ) context),(data),(dataLen),((kss_kose_object_t * ) keyObjects),(keyObjectCount),(tunnelType))
#       define kss_tunnel_context_free(context) \
            kss_kose_tunnel_context_free(((kss_kose_tunnel_context_t * ) context))
#   endif /* (KSS_HAVE_KSS == 1) */
/* clang-format on */

#endif /* KSS_HAVE_APPLET_KOSE_IOT */
#ifdef __cplusplus
} // extern "C"
#endif /* __cplusplus */

#endif /* FSL_KSS_KOSE_APIS_H */
