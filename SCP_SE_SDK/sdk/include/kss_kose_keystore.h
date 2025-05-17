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
 * This API does not do anything special on SE05X.
 */
kss_status_t kss_kose_key_store_allocate(kss_kose_key_store_t *keyStore, uint32_t keyStoreId);
