/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef KSS_APIS_INC_KONA_KSS_MBEDTLS_TYPES_H_
#define KSS_APIS_INC_KONA_KSS_MBEDTLS_TYPES_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <kona_kss_api.h>

#if defined(KSS_USE_FTR_FILE)
#include "kona_kss_ftr.h"
#else
#include "kona_kss_ftr_default.h"
#endif

#if KSS_HAVE_HOSTCRYPTO_MBEDTLS

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "kona_kss_keyid_map.h"
#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ccm.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>

/**
 * @addtogroup kss_sw_mbedtls
 * @{
 */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define KSS_SUBSYSTEM_TYPE_IS_MBEDTLS(subsystem) (subsystem == kType_KSS_mbedTLS)

#define KSS_SESSION_TYPE_IS_MBEDTLS(session) (session && KSS_SUBSYSTEM_TYPE_IS_MBEDTLS(session->subsystem))

#define KSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore) (keyStore && KSS_SESSION_TYPE_IS_MBEDTLS(keyStore->session))

#define KSS_OBJECT_TYPE_IS_MBEDTLS(pObject) (pObject && KSS_KEY_STORE_TYPE_IS_MBEDTLS(pObject->keyStore))

#define KSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context) (context && KSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define KSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context) (context && KSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define KSS_SYMMETRIC_TYPE_IS_MBEDTLS(context) (context && KSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define KSS_MAC_TYPE_IS_MBEDTLS(context) (context && KSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define KSS_RNG_CONTEXT_TYPE_IS_MBEDTLS(context) (context && KSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define KSS_DIGEST_TYPE_IS_MBEDTLS(context) (context && KSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define KSS_AEAD_TYPE_IS_MBEDTLS(context) (context && KSS_SESSION_TYPE_IS_MBEDTLS(context->session))

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

struct _kss_mbedtls_session;

typedef struct _kss_mbedtls_session
{
    /*! Indicates which security subsystem is selected to be used. */
    kss_type_t subsystem;

    mbedtls_entropy_context *entropy;
    mbedtls_ctr_drbg_context *ctr_drbg;

#ifdef MBEDTLS_FS_IO
    /* Root Path for persitant key store */
    const char *szRootPath;
#endif
} kss_mbedtls_session_t;

struct _kss_mbedtls_object;

typedef struct _kss_mbedtls_key_store
{
    kss_mbedtls_session_t *session;

#ifdef MBEDTLS_FS_IO
    /*! Implementation specific part */
    struct _kss_mbedtls_object **objects;
    uint32_t max_object_count;

    keyStoreTable_t *keystore_shadow;
#endif
} kss_mbedtls_key_store_t;

typedef struct _kss_mbedtls_object
{
    /*! key store holding the data and other properties */
    kss_mbedtls_key_store_t *keyStore;
    /*! Object types */
    uint32_t objectType;
    uint32_t cipherType;
    /*! Application specific key identifier. The keyId is kept in the key  store
     * along with the key data and other properties. */
    uint32_t keyId;

    /*! Implementation specific part */
    /** Contents are malloced, so must be freed */
    uint32_t contents_must_free : 1;
    /** Type of key. Persistnet/trainsient @ref kss_key_object_mode_t */
    uint32_t keyMode : 3;
    /** Max size allocated */
    size_t contents_max_size;
    size_t contents_size;
    size_t keyBitLen;
    uint32_t user_id;
    kss_mode_t purpose;
    kss_access_permission_t accessRights;
    /* malloced / referenced contents */
    void *contents;
} kss_mbedtls_object_t;

typedef struct _kss_mbedtls_derive_key
{
    kss_mbedtls_session_t *session;
    kss_mbedtls_object_t *keyObject;
    kss_algorithm_t algorithm; /*!  */
    kss_mode_t mode;           /*!  */

} kss_mbedtls_derive_key_t;

typedef struct _kss_mbedtls_asymmetric
{
    kss_mbedtls_session_t *session;
    kss_mbedtls_object_t *keyObject;
    kss_algorithm_t algorithm; /*!  */
    kss_mode_t mode;           /*!  */

} kss_mbedtls_asymmetric_t;

typedef struct _kss_mbedtls_symmetric
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_mbedtls_session_t *session;
    kss_mbedtls_object_t *keyObject; /*!< Reference to key and it's properties. */
    kss_algorithm_t algorithm;       /*!  */
    kss_mode_t mode;                 /*!  */
    mbedtls_cipher_context_t *cipher_ctx;
    uint8_t cache_data[16];
    size_t cache_data_len;

} kss_mbedtls_symmetric_t;

typedef struct _kss_mbedtls_mac
{
    kss_mbedtls_session_t *session;
    kss_mbedtls_object_t *keyObject; /*! Reference to key and it's properties. */
    kss_algorithm_t algorithm;       /*!  */
    kss_mode_t mode;                 /*!  */

    /*! Implementation specific part */
    mbedtls_cipher_context_t *cipher_ctx; /*For init- update -finish*/
    mbedtls_md_context_t *HmacCtx;
} kss_mbedtls_mac_t;

typedef struct _kss_mbedtls_aead
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_mbedtls_session_t *session;
    kss_mbedtls_object_t *keyObject; /*!< Reference to key and it's properties. */
    kss_algorithm_t algorithm;       /*!<  */
    kss_mode_t mode;                 /*!<  */

    /*! Implementation specific part */
    mbedtls_gcm_context *gcm_ctx; /*!< Reference to gcm context. */
    mbedtls_ccm_context *ccm_ctx; /*!< Reference to ccm context. */
    uint8_t *pNonce;              /*!< Reference to IV. */
    size_t nonceLen;              /*!< Store IV len. */
    const uint8_t *pCcm_aad;      /*!< Reference to AAD */
    size_t ccm_aadLen;            /*!< Store AAD len. */
    uint8_t *pCcm_data;           /*!< Ref to CCM data dynamic allocated.. */
    size_t ccm_dataTotalLen;      /*!< Store CCM data total len. */
    size_t ccm_dataoffset;        /*!< Store CCM data offset. */
    uint8_t cache_data[16];       /*!< Cache for GCM data  */
    size_t cache_data_len;        /*!< Store GCM Cache len*/
} kss_mbedtls_aead_t;

typedef struct _kss_mbedtls_digest
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_mbedtls_session_t *session;
    kss_algorithm_t algorithm; /*!<  */
    kss_mode_t mode;           /*!<  */
    /*! Full digest length per algorithm definition. This field is initialized along with algorithm. */
    size_t digestFullLen;
    /*! Implementation specific part */
    mbedtls_md_context_t md_ctx;
} kss_mbedtls_digest_t;

typedef struct
{
    kss_mbedtls_session_t *session;

} kss_mbedtls_rng_context_t;

#define kss_mbedtls_tunnel_t kss_tunnel_t

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

#ifdef MBEDTLS_FS_IO

/** Store key inside persistant key store */
kss_status_t ks_mbedtls_store_key(const kss_mbedtls_object_t *kss_key);

kss_status_t ks_mbedtls_load_key(kss_mbedtls_object_t *kss_key, keyStoreTable_t *keystore_shadow, uint32_t extKeyId);

kss_status_t ks_mbedtls_remove_key(const kss_mbedtls_object_t *kss_key);

kss_status_t ks_mbedtls_fat_update(kss_mbedtls_key_store_t *keyStore);

#endif /* MBEDTLS_FS_IO */

/* Low Level API Key object create */
kss_status_t ks_mbedtls_key_object_create(kss_mbedtls_object_t *keyObject,
    uint32_t keyId,
    kss_key_part_t keyPart,
    kss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t keyMode);

/** @}  */

#endif /* KSS_HAVE_HOSTCRYPTO_MBEDTLS */

#endif /* KSS_APIS_INC_KONA_KSS_MBEDTLS_TYPES_H_ */
