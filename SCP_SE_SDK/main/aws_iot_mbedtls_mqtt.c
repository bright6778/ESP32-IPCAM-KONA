
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/ctr_drbg.h"

#include <string.h>
#include <stdio.h>
#include "kona_kss_kose_config.h"
#include "kona_kss_api.h"
#include "kss_kose_mbedtls.h"
#include "kss_kose_keystore.h"

#ifdef DEBUG_PRINT
#include "debug.h"
#endif

#define ONLY_MBEDTLS_TEST_CERTFILE  // device keypair & CA Cert in file
//#define ONLY_MBEDTLS_TEST         // no use SE keypair
#define AWS_CA_CERT_ECC
#define MBEDTLS_RANDOM_USE_SE       // SE에서 Random을 생성.

#define AWS_IOT_PORT     "8883"

#define AWS_IOT_ENDPOINT "a34vuzhubahjfj-ats.iot.ap-northeast-2.amazonaws.com"
#define MQTT_CLIENT_ID   "ee2e9203f0a0971c599888fb8b67e3a1882626cd-ucnam"
#define MQTT_TOPIC       "client/test/ee2e9203f0a0971c599888fb8b67e3a1882626cd/la/123456"
#define MQTT_PAYLOAD     "hello aws iot"

static const char *TAG = "aws_iot_mbedtls_mqtt.c";

const int sdk_recommended_ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
#ifndef AWS_CA_CERT_ECC
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
#endif
    0
};

/*The size of the client certificate should be checked when script is used to store it in GP storage and updated here */
#define SIZE_CLIENT_CERTIFICATE 2048

extern const char client_cert_start[] asm("_binary_client_crt_start");
extern const char client_cert_end[] asm("_binary_client_crt_end");
extern const char client_key_start[] asm("_binary_client_key_start");
extern const char client_key_end[] asm("_binary_client_key_end");
extern const char root_cert_auth_start[]   asm("_binary_root_cert_auth_crt_start");
extern const char root_cert_auth_end[]   asm("_binary_root_cert_auth_crt_end");
extern const char root_cert_auth_ecc_start[]   asm("_binary_root_cert_auth_ecc_crt_start");
extern const char root_cert_auth_ecc_end[]   asm("_binary_root_cert_auth_ecc_crt_end");
extern void *se_key_object;                        // SE 핸들

void my_debug(void *ctx, int level,
              const char *file, int line,
              const char *str)
{
    ((void) level);
    fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
}

int mqtt_send_connect(mbedtls_ssl_context *ssl, const char *client_id)
{
    unsigned char buf[512];
    size_t len = 0;

    buf[len++] = 0x10; // MQTT CONNECT packet type
    buf[len++] = 12 + strlen(client_id); // remaining length

    // Variable header
    buf[len++] = 0x00; buf[len++] = 0x04; // length
    buf[len++] = 'M'; buf[len++] = 'Q'; buf[len++] = 'T'; buf[len++] = 'T';
    buf[len++] = 0x04; // MQTT version 3.1.1
    buf[len++] = 0x02; // clean session
    buf[len++] = 0x00; buf[len++] = 60; // keep alive

    // Payload
    buf[len++] = 0x00; buf[len++] = strlen(client_id);
    memcpy(&buf[len], client_id, strlen(client_id));
    len += strlen(client_id);
    
    return mbedtls_ssl_write(ssl, buf, len);
}

int mqtt_send_publish(mbedtls_ssl_context *ssl, const char *topic, const char *payload)
{
    unsigned char buf[512];
    size_t len = 0;
    size_t topic_len = strlen(topic);
    size_t payload_len = strlen(payload);

    buf[len++] = 0x30; // PUBLISH packet
    buf[len++] = 2 + topic_len + payload_len;
    buf[len++] = 0x00; buf[len++] = topic_len;
    memcpy(&buf[len], topic, topic_len); len += topic_len;
    memcpy(&buf[len], payload, payload_len); len += payload_len;

    return mbedtls_ssl_write(ssl, buf, len);
}

int mqtt_read_response(mbedtls_ssl_context *ssl)
{
    unsigned char buf[512];
    int ret = mbedtls_ssl_read(ssl, buf, sizeof(buf));

    if (ret > 0) {
        LOGI(TAG, "[MQTT] Received %d bytes from broker:", ret);
        debug_showframe("buf", buf, ret);

        if (buf[0] == 0x20 && ret >= 4) {
            if (buf[3] == 0x00) {
                LOGI(TAG, "[MQTT] CONNACK: Connection Accepted");
            } else {
                LOGE(TAG, "[MQTT] CONNACK: Connection Refused Reason Code: 0x%02X\n", buf[3]);
            }
        }

        return ret;
    } else if (ret == 0) {
        LOGI(TAG, "[MQTT] Connection closed by broker.");
    } else {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        LOGE(TAG, "[MQTT] Read error: -0x%04X - %s\n", -ret, err_buf);
    }

    return ret;
}


void aws_iot_mbedtls_mqtt_test(kss_session_t *session)
{
    char err_buf[256];
    int ret = 0;
    
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert, client_cert;
    mbedtls_pk_context client_key;
    
    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&client_cert);
    mbedtls_pk_init(&client_key);

    // mbedtls debug setting
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    mbedtls_debug_set_threshold(4);

#ifndef MBEDTLS_RANDOM_USE_SE
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *personalization = "my_tls_rng";  // optional

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                 mbedtls_entropy_func,
                                 &entropy,
                                 (const unsigned char *)personalization,
                                 strlen(personalization));
#else
    kss_rng_context_t rng_ctx;
#endif  // MBEDTLS_RANDOM_USE_SE
    // TLS config
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    
    kss_object_t keyobject; // device private key object
    kss_object_t dev_cert;  // device cert object
    kss_object_t pub_obj;   // CA cert object
    
    kss_key_store_t keystore;
    kss_status_t kss_status;
    
    memset(&keystore, 0, sizeof(kss_key_store_t));
    
    kss_status = kss_key_store_context_init(&keystore, session);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init failed res : %d", kss_status);
        return;
    }

    ////////////////////////////////////////////////////////////////////////
    //////////////////// device private key handle /////////////////////////
    ////////////////////////////////////////////////////////////////////////
    // keypair init
    kss_status = kss_key_object_init(&keyobject, &keystore);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init failed res : %d", kss_status);
        return;
    }

    kss_status = kss_key_object_get_handle(&keyobject, 0x0100);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_get_handle failed res : %d", kss_status);
        return;
    }
#ifdef ONLY_MBEDTLS_TEST
#ifdef ONLY_MBEDTLS_TEST_CERTFILE
    //only test
    ret = mbedtls_pk_parse_key(&client_key, (const unsigned char *)client_key_start, client_key_end - client_key_start, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
#endif // ONLY_MBEDTLS_TEST_CERTFILE
#endif // ONLY_MBEDTLS_TEST
    ////////////////////////////////////////////////////////////////////////
    //////////////////////// device cert handle ////////////////////////////
    ////////////////////////////////////////////////////////////////////////
    // keypair init
    kss_status = kss_key_object_init(&dev_cert, &keystore);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init failed res : %d", kss_status);
        return;
    }

    kss_status = kss_key_object_get_handle(&dev_cert, 0x0700);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_get_handle failed res : %d", kss_status);
        return;
    }

    ////////////////////////////////////////////////////////////////////////
    //////////////////////////// CA cert handle ////////////////////////////
    ////////////////////////////////////////////////////////////////////////
    // CA object init
    kss_status = kss_key_object_init(&pub_obj, &keystore);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init failed res : %d", kss_status);
        return;
    }

    kss_status = kss_key_object_get_handle(&pub_obj, 0x0800);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_get_handle failed res : %d", kss_status);
        return;
    }

#ifdef ONLY_MBEDTLS_TEST_CERTFILE
    /* doc+:load-certificate-from-se */
    ret = mbedtls_x509_crt_parse(&client_cert, (const unsigned char *)client_cert_start, (client_cert_end - client_cert_start));    //저장된 cert 사용 시
#else
    // SE에 저장된 public key를 가져오는 부분
    size_t KeyBitLen = SIZE_CLIENT_CERTIFICATE * 8;
    size_t KeyByteLen = SIZE_CLIENT_CERTIFICATE;

    kss_status = kss_key_store_get_key(&keystore, &dev_cert, aclient_cer, &KeyByteLen, &KeyBitLen);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_get_key failed res : %d", kss_status);
        return;
    }

    ret = mbedtls_x509_crt_parse_der(&client_cert, (const unsigned char *)aclient_cer, sizeof(aclient_cer));
    if (ret < 0) {
        LOGE(TAG, " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int) -ret);
        return;
    }
#endif

    

    ////////////////////////////////////////////////////////////////////////
    //////////////////////// Load the trusted CA////////////////////////////
    ////////////////////////////////////////////////////////////////////////
#ifdef AWS_CA_CERT_ECC
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)root_cert_auth_ecc_start, (root_cert_auth_ecc_end - root_cert_auth_ecc_start)); 
#else
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)root_cert_auth_start, (root_cert_auth_end - root_cert_auth_start)); 
#endif

#ifndef ONLY_MBEDTLS_TEST
    // SE에서 CA Cert 보관 시
    //mbedtls_pk_free(&cacert.pk); //SE에서 CA Cert 보관 시엔 기존 cacert를 free    
    ret = kss_mbedtls_associate_pubkey(&cacert.pk, &pub_obj);
    LOGD(TAG, "=== cacert Context 상태 체크 ===");
    LOGD(TAG, "cacert.pk_info pointer         = %p", cacert.pk.private_pk_info);
    LOGD(TAG, "cacert.pk_info->sign pointer   = %p", cacert.pk.private_pk_info ? cacert.pk.private_pk_info->verify_func : NULL);
    LOGD(TAG, "cacert.pk_ctx pointer          = %p", cacert.pk.private_pk_ctx);
    LOGD(TAG, "cacert private_grp.id pointer  = %p", &((mbedtls_ecp_keypair *)cacert.pk.private_pk_ctx)->private_grp.id);
    LOGD(TAG, "cacert pax_ctx.id val          = %d", ((mbedtls_ecp_keypair *)cacert.pk.private_pk_ctx)->private_grp.id);

/*    
    //mbedtls_pk_free(&cacert.pk);
    kss_kose_set_kss_keystore(&keystore);
    #if defined(MBEDTLS_ECDSA_VERIFY_ALT)
        LOGI(TAG, "MBEDTLS_ECDSA_VERIFY_ALT define");
    #endif
*/
    if(kss_mbedtls_associate_keypair(&client_key, &keyobject) != 0){
        LOGE(TAG, "kss_mbedtls_associate_keypair failed");
        return;
    }

#endif
   
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);  //MBEDTLS_SSL_VERIFY_REQUIRED(서명 검증) MBEDTLS_SSL_VERIFY_NONE(검증X)
    mbedtls_ssl_conf_ciphersuites(&conf, sdk_recommended_ciphersuites);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_own_cert(&conf, &client_cert, &client_key);
#ifndef MBEDTLS_RANDOM_USE_SE
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#else
    kss_rng_context_init(&rng_ctx, session);
    mbedtls_ssl_conf_rng(&conf, kss_mbedtls_se_random, &rng_ctx);
#endif
    if(mbedtls_ssl_setup(&ssl, &conf) != 0){
        LOGE(TAG, "mbedtls_ssl_setup failed");
        return;
    }
    if(mbedtls_ssl_set_hostname(&ssl, AWS_IOT_ENDPOINT)){
        LOGE(TAG, "mbedtls_ssl_set_hostname failed");
        return;
    }

    mbedtls_net_connect(&net, AWS_IOT_ENDPOINT, AWS_IOT_PORT, MBEDTLS_NET_PROTO_TCP);
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
/*
    LOGD(TAG, "=== client_key Context 상태 체크 ===");
    LOGD(TAG, "client_key.pk_info pointer         = %p", client_key.private_pk_info);
    LOGD(TAG, "client_key.pk_info->sign pointer   = %p", client_key.private_pk_info ? client_key.private_pk_info->sign_func : NULL);
    LOGD(TAG, "client_key.pk_ctx pointer          = %p", client_key.private_pk_ctx);
    LOGD(TAG, "client_key private_grp.id pointer  = %p", &((mbedtls_ecp_keypair *)client_key.private_pk_ctx)->private_grp.id);
    LOGD(TAG, "client_key pax_ctx.id val          = %d", ((mbedtls_ecp_keypair *)client_key.private_pk_ctx)->private_grp.id);
*/    
    // TLS handshake
    ret = mbedtls_ssl_handshake(&ssl);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        LOGE(TAG, "TLS handshake failed: -0x%04X - %s\n", ret, err_buf);
        return;
    }

    // MQTT 연결 및 메시지 전송
    ret = mqtt_send_connect(&ssl, MQTT_CLIENT_ID);
    if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        LOGE(TAG, "mqtt_send_connect failed: -0x%04X - %s\n", -ret, err_buf);
    } else {
        LOGI(TAG, "mqtt_send_connect success! Wrote %d bytes\n", ret);
    }
    
    ret = mqtt_send_publish(&ssl, MQTT_TOPIC, MQTT_PAYLOAD);
    if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        LOGE(TAG, "mqtt_send_publish failed: -0x%04X - %s\n", -ret, err_buf);
    } else {
        LOGI(TAG, "mqtt_send_publish success! Wrote %d bytes\n", ret);
    }

    ret = mqtt_read_response(&ssl);
    if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        LOGE(TAG, "mqtt_read_response failed: -0x%04X - %s\n", -ret, err_buf);
    } else {
        LOGI(TAG, "mqtt_read_response success! Wrote %d bytes\n", ret);
    }

    LOGI(TAG, "MQTT message sent to AWS IoT Core success!");

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&net);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&client_cert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&client_key);
} 
