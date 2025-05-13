#include "kona_kss_api.h"
#include "kss_kose_rng.h"
#include "kss_kose_session.h"
#include "kss_kose_session.h"

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

kss_status_t kss_rng_context_init(kss_rng_context_t *context, kss_session_t *session)
{
   return kss_kose_rng_context_init(context , session);
}

kss_status_t kss_rng_get_random(kss_rng_context_t *context, uint8_t *random_data, size_t dataLen)
{
    LOG_D("FN: %s", __FUNCTION__);
    return kss_kose_rng_get_random(context, random_data, dataLen);
}

kss_status_t kss_rng_context_free(kss_rng_context_t *context)
{
    LOG_D("FN: %s", __FUNCTION__);
    return kss_kose_rng_context_free(context);

}