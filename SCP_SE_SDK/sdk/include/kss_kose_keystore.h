/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#include "kona_kss_kose_types.h"

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

void kss_kose_set_kss_keystore(kss_key_store_t *ksskeystore);

/** @copydoc kss_key_store_get_key
 *
 */
kss_status_t kss_kose_key_store_get_key(
    kss_kose_key_store_t *keyStore, 
    kss_kose_object_t *keyObject, 
    uint8_t *key, 
    size_t *keylen, 
    size_t *pKeyBitLen);

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
