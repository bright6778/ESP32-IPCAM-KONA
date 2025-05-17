/** @file */
#ifdef __cplusplus
extern "C" {
#endif

#include "kona_kss_api.h"
#include "kona_kss_kose_types.h"
#include "kona_kss_ftr_default.h"
#include "kose_APDU_impl.h"
#include "kss_kose_keystore.h"
#include "debug.h"

static const char *TAG = "kss_kose_keystore.c";

/* ************************************************************************** */
/* Functions : kss_kose_keystore                                             */
/* ************************************************************************** */

kss_status_t kss_kose_key_store_context_init(kss_kose_key_store_t *keyStore, kss_kose_session_t *session)
{
    kss_status_t retval = kStatus_KSS_Success;
    if (keyStore == NULL) {
        return kStatus_KSS_Fail;
    }
    memset(keyStore, 0, sizeof(*keyStore));
    keyStore->session = session;
    return retval;
}

kss_status_t kss_kose_key_store_allocate(kss_kose_key_store_t *keyStore, uint32_t keyStoreId)
{
    AX_UNUSED_ARG(keyStore);
    AX_UNUSED_ARG(keyStoreId);
    return kStatus_KSS_Success;
}

#ifdef __cplusplus
}
#endif