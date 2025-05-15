#include "kona_kss_kose_types.h"
#include "kona_kss_api.h"
#include "kss_kose_rng.h"
#include "kss_kose_session.h"
#include "kss_kose_asymmetric.h"

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

kss_status_t kss_asymmetric_context_init(kss_asymmetric_t *context,
    kss_session_t *session,
    kss_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode)
{
#if KSS_HAVE_SSCP
    if (KSS_SESSION_TYPE_IS_SSCP(session)) {
        kss_sscp_asymmetric_t *sscp_context = (kss_sscp_asymmetric_t *)context;
        kss_sscp_session_t *sscp_session    = (kss_sscp_session_t *)session;
        kss_sscp_object_t *sscp_keyObject   = (kss_sscp_object_t *)keyObject;
        KSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        KSS_ASSERT(sizeof(*sscp_session) <= sizeof(*session));
        KSS_ASSERT(sizeof(*sscp_keyObject) <= sizeof(*keyObject));
        return kss_sscp_asymmetric_context_init(sscp_context, sscp_session, sscp_keyObject, algorithm, mode);
    }
#endif /* KSS_HAVE_SSCP */
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_SESSION_TYPE_IS_KOSE(session)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        kss_kose_session_t *kose_session    = (kss_kose_session_t *)session;
        kss_kose_object_t *kose_keyObject   = (kss_kose_object_t *)keyObject;
        return kss_kose_asymmetric_context_init(kose_context, kose_session, kose_keyObject, algorithm, mode);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (KSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        kss_mbedtls_asymmetric_t *mbedtls_context = (kss_mbedtls_asymmetric_t *)context;
        kss_mbedtls_session_t *mbedtls_session    = (kss_mbedtls_session_t *)session;
        kss_mbedtls_object_t *mbedtls_keyObject   = (kss_mbedtls_object_t *)keyObject;
        KSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        KSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        KSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return kss_mbedtls_asymmetric_context_init(
            mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if KSS_HAVE_HOSTCRYPTO_OPENSSL
    if (KSS_SESSION_TYPE_IS_OPENSSL(session)) {
        kss_openssl_asymmetric_t *openssl_context = (kss_openssl_asymmetric_t *)context;
        kss_openssl_session_t *openssl_session    = (kss_openssl_session_t *)session;
        kss_openssl_object_t *openssl_keyObject   = (kss_openssl_object_t *)keyObject;
        KSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        KSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        KSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return kss_openssl_asymmetric_context_init(
            openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_asymmetric_encrypt(
    kss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
#if KSS_HAVE_SSCP
    if (KSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        kss_sscp_asymmetric_t *sscp_context = (kss_sscp_asymmetric_t *)context;
        return kss_sscp_asymmetric_encrypt(sscp_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_SSCP */
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        return kss_kose_asymmetric_encrypt(kose_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (KSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        kss_mbedtls_asymmetric_t *mbedtls_context = (kss_mbedtls_asymmetric_t *)context;
        return kss_mbedtls_asymmetric_encrypt(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if KSS_HAVE_HOSTCRYPTO_OPENSSL
    if (KSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        kss_openssl_asymmetric_t *openssl_context = (kss_openssl_asymmetric_t *)context;
        return kss_openssl_asymmetric_encrypt(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_asymmetric_decrypt(
    kss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
#if KSS_HAVE_SSCP
    if (KSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        kss_sscp_asymmetric_t *sscp_context = (kss_sscp_asymmetric_t *)context;
        return kss_sscp_asymmetric_decrypt(sscp_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_SSCP */
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        return kss_kose_asymmetric_decrypt(kose_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (KSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        kss_mbedtls_asymmetric_t *mbedtls_context = (kss_mbedtls_asymmetric_t *)context;
        return kss_mbedtls_asymmetric_decrypt(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if KSS_HAVE_HOSTCRYPTO_OPENSSL
    if (KSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        kss_openssl_asymmetric_t *openssl_context = (kss_openssl_asymmetric_t *)context;
        return kss_openssl_asymmetric_decrypt(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_asymmetric_sign_digest(
    kss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
#if KSS_HAVE_SSCP
    if (KSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        kss_sscp_asymmetric_t *sscp_context = (kss_sscp_asymmetric_t *)context;
        return kss_sscp_asymmetric_sign_digest(sscp_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_SSCP */
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        return kss_kose_asymmetric_sign_digest(kose_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (KSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        kss_mbedtls_asymmetric_t *mbedtls_context = (kss_mbedtls_asymmetric_t *)context;
        return kss_mbedtls_asymmetric_sign_digest(mbedtls_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if KSS_HAVE_HOSTCRYPTO_OPENSSL
    if (KSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        kss_openssl_asymmetric_t *openssl_context = (kss_openssl_asymmetric_t *)context;
        return kss_openssl_asymmetric_sign_digest(openssl_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_KSS_InvalidArgument;
}

kss_status_t kss_asymmetric_verify_digest(
    kss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen)
{
#if KSS_HAVE_SSCP
    if (KSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        kss_sscp_asymmetric_t *sscp_context = (kss_sscp_asymmetric_t *)context;
        return kss_sscp_asymmetric_verify_digest(sscp_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_SSCP */
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        return kss_kose_asymmetric_verify_digest(kose_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (KSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        kss_mbedtls_asymmetric_t *mbedtls_context = (kss_mbedtls_asymmetric_t *)context;
        return kss_mbedtls_asymmetric_verify_digest(mbedtls_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if KSS_HAVE_HOSTCRYPTO_OPENSSL
    if (KSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        kss_openssl_asymmetric_t *openssl_context = (kss_openssl_asymmetric_t *)context;
        return kss_openssl_asymmetric_verify_digest(openssl_context, digest, digestLen, signature, signatureLen);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_KSS_InvalidArgument;
}

void kss_asymmetric_context_free(kss_asymmetric_t *context)
{
#if KSS_HAVE_SSCP
    if (KSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        kss_sscp_asymmetric_t *sscp_context = (kss_sscp_asymmetric_t *)context;
        kss_sscp_asymmetric_context_free(sscp_context);
    }
#endif /* KSS_HAVE_SSCP */
#if KSS_HAVE_APPLET_KOSE_IOT
    if (KSS_ASYMMETRIC_TYPE_IS_KOSE(context)) {
        kss_kose_asymmetric_t *kose_context = (kss_kose_asymmetric_t *)context;
        kss_kose_asymmetric_context_free(kose_context);
    }
#endif /* KSS_HAVE_APPLET_KOSE_IOT */
#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (KSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        kss_mbedtls_asymmetric_t *mbedtls_context = (kss_mbedtls_asymmetric_t *)context;
        kss_mbedtls_asymmetric_context_free(mbedtls_context);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if KSS_HAVE_HOSTCRYPTO_OPENSSL
    if (KSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        kss_openssl_asymmetric_t *openssl_context = (kss_openssl_asymmetric_t *)context;
        kss_openssl_asymmetric_context_free(openssl_context);
    }
#endif /* KSS_HAVE_HOSTCRYPTO_OPENSSL */
}

#if 0
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
#endif
