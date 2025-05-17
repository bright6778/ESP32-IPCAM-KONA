/**
 * @addtogroup kss_kose_keyobj
 * @{
 */
/** @copydoc kss_key_object_init
 *
 */
kss_status_t kss_kose_key_object_init(kss_kose_object_t *keyObject, kss_kose_key_store_t *keyStore);

kss_status_t kss_kose_key_object_get_handle(kss_kose_object_t *keyObject, uint32_t keyId);
