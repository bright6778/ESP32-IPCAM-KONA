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

/** @copydoc kss_key_store_get_key
 *
 */
kss_status_t kss_kose_key_store_get_key(
    kss_kose_key_store_t *keyStore, kss_kose_object_t *keyObject, uint8_t *key, size_t *keylen, size_t *pKeyBitLen);
