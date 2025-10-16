
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
#include "kona_kss_debug.h"
#endif

//#define ONLY_MBEDTLS_TEST_CERTFILE  // device keypair & CA Cert in file
//#define ONLY_MBEDTLS_TEST           // no use SE keypair
//#define AWS_CA_CERT_ECC             // CA Cert Algorithm used ECC(default : RSA)  
#define MBEDTLS_RANDOM_USE_SE       // SE에서 Random을 생성.
//#define DEVICE_KEY_ALG_ECC          // Device 인증서 알고리즘이 ECC일 경우 활성화.(default : RSA)

#define AWS_IOT_PORT     "8883"

#define AWS_IOT_ENDPOINT "a34vuzhubahjfj-ats.iot.ap-northeast-2.amazonaws.com"
#define MQTT_CLIENT_ID   "ee2e9203f0a0971c599888fb8b67e3a1882626cd-kona"
#define MQTT_TOPIC       "client/test/ee2e9203f0a0971c599888fb8b67e3a1882626cd/la/123456"
#define MQTT_PAYLOAD     "{\"message\":\"hello aws iot\"}" //"hello aws iot"

static const char *TAG = "aws_iot_mbedtls_mqtt.c";

const int sdk_recommended_ciphersuites[] = {
#ifdef AWS_CA_CERT_ECC
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
#else   // AWS_CA_CERT_ECC
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
#endif  // AWS_CA_CERT_ECC
    0
};

/*The size of the client certificate should be checked when script is used to store it in GP storage and updated here */
#define SIZE_CLIENT_CERTIFICATE 2048
#ifdef ESP_PLATFORM
#ifdef AWS_CA_CERT_ECC
extern const unsigned char root_cert_auth_ecc_start[]   asm("_binary_root_cert_auth_ecc_crt_start");
extern const unsigned char root_cert_auth_ecc_end[]   asm("_binary_root_cert_auth_ecc_crt_end");
#else   // AWS_CA_CERT_ECC
extern const unsigned char root_cert_auth_start[]   asm("_binary_root_cert_auth_crt_start");
extern const unsigned char root_cert_auth_end[]   asm("_binary_root_cert_auth_crt_end");
#endif  //AWS_CA_CERT_ECC
#ifdef DEVICE_KEY_ALG_ECC
extern const unsigned char client_cert_start[]   asm("_binary_client_crt_start");
extern const unsigned char client_cert_end[]   asm("_binary_client_crt_end");
extern const unsigned char client_key_start[]   asm("_binary_client_key_start");
extern const unsigned char client_key_end[]   asm("_binary_client_key_end");
#else   // DEVICE_KEY_ALG_ECC
extern const unsigned char client_cert_start[]   asm("_binary_client_rsa_crt_start");
extern const unsigned char client_cert_end[]   asm("_binary_client_rsa_crt_end");
extern const unsigned char client_key_start[]   asm("_binary_client_rsa_key_start");
extern const unsigned char client_key_end[]   asm("_binary_client_rsa_key_end");
#endif  // DEVICE_KEY_ALG_ECC
#else   // ESP_PLATFORM
extern unsigned char *root_cert_auth_ecc_start = NULL;
extern unsigned char *root_cert_auth_ecc_end   = NULL;
extern unsigned char *client_cert_start = NULL;
extern unsigned char *client_cert_end   = NULL;
extern unsigned char *client_key_start = NULL;
extern unsigned char *client_key_end   = NULL;
#endif  //ESP_PLATFORM
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
/*
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
*/
int mqtt_send_publish(mbedtls_ssl_context *ssl, const char *topic, const char *payload)
{
    unsigned char buf[512];
    size_t len = 0;
    size_t topic_len = strlen(topic);
    size_t payload_len = strlen(payload);

    buf[len++] = 0x30; // Fixed header: PUBLISH, QoS 0

    // Variable length encoding for remaining length
    size_t rem_len = 2 + topic_len + payload_len;
    do {
        uint8_t encoded_byte = rem_len % 128;
        rem_len /= 128;
        if (rem_len > 0)
            encoded_byte |= 0x80;
        buf[len++] = encoded_byte;
    } while (rem_len > 0);

    // Topic length (2 bytes, big endian)
    buf[len++] = (topic_len >> 8) & 0xFF;
    buf[len++] = topic_len & 0xFF;

    memcpy(&buf[len], topic, topic_len); len += topic_len;
    memcpy(&buf[len], payload, payload_len); len += payload_len;

    return mbedtls_ssl_write(ssl, buf, len);
}
/*
int mqtt_read_response(mbedtls_ssl_context *ssl)
{
    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));
    int ret = mbedtls_ssl_read(ssl, buf, sizeof(buf));

    if (ret > 0) {
        LOGI(TAG, "[MQTT] Received %d bytes from broker:", ret);
        kss_debug_showframe("buf", buf, ret);

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
*/
int mqtt_read_response(mbedtls_ssl_context *ssl, unsigned char* rstbuf, size_t maxLen)
{
    int ret = mbedtls_ssl_read(ssl, rstbuf, maxLen);

    if (ret > 0) {
        if (rstbuf[0] == 0x20 && ret >= 4) {
            if (rstbuf[3] == 0x00) {
                LOGI(TAG, "[MQTT] CONNACK: Connection Accepted");
            } else {
                LOGE(TAG, "[MQTT] CONNACK: Connection Refused Reason Code: 0x%02X\n", rstbuf[3]);
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

int load_cert_to_buffer(const char *filepath, unsigned char **start, unsigned char **end)
{
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        printf("fopen\n");
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buf = malloc(filesize + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    size_t read_size = fread(buf, 1, filesize, f);
    if (read_size != filesize) {
        printf("파일을 모두 읽지 못했습니다. 읽은 바이트 수: %zu\n", read_size);
        fclose(f);
        return -1;
    }
    fclose(f);

    buf[filesize] = '\0'; // null-terminate (PEM 파일일 경우)
    *start = buf;
    *end = buf + filesize;
    return 0;
}

void aws_iot_mbedtls_mqtt_test(kss_session_t *session)
{
    char err_buf[256];
    int ret = 0;
    size_t null_size = 0;
    
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
    //mbedtls_debug_set_threshold(4);

    uint32_t ca_public_id = 0;
    uint32_t device_privkey_id = 0;
    uint32_t device_cert_id = 0;
    size_t dataSize = 0;

#ifdef AWS_CA_CERT_ECC
    ca_public_id = 0x0200;
#else   // AWS_CA_CERT_ECC
    ca_public_id = 0x0B00;
#endif  // AWS_CA_CERT_ECC

#ifdef DEVICE_KEY_ALG_ECC
    device_privkey_id = 0x0100;
    device_cert_id = 0x0700;
#else
    device_privkey_id = 0x0A00;
    device_cert_id = 0x0701;
#endif  // DEVICE_KEY_ALG_ECC

#ifndef ESP_PLATFORM
#ifdef AWS_CA_CERT_ECC
    if(load_cert_to_buffer("./certs/root_cert_auth_ecc.crt", &root_cert_auth_ecc_start, &root_cert_auth_ecc_end) != 0){
        printf("load_cert_to_buffer failed\n");
        return;
    }
#else
    if(load_cert_to_buffer("./certs/root_cert_auth.crt", &root_cert_auth_start, &root_cert_auth_end) != 0){
        printf("load_cert_to_buffer failed\n");
        return;
    }
#endif //AWS_CA_CERT_ECC
    null_size = 1;
#endif
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
    
    kss_object_t dev_priv;  // device private key object
    kss_object_t dev_pub;   // device public key object
    kss_object_t dev_cert;  // device cert object
    kss_object_t pub_obj;   // CA public key object
    
    kss_key_store_t keystore;
    kss_status_t kss_status;
    
    kss_status = kss_key_store_context_init(&keystore, session);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init failed res : %d", kss_status);
        return;
    }

    ////////////////////////////////////////////////////////////////////////
    //////////////////// device private key handle /////////////////////////
    ////////////////////////////////////////////////////////////////////////
    // keypair init
    kss_status = kss_key_object_init(&dev_priv, &keystore);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init failed res : %d", kss_status);
        return;
    }

    kss_status = kss_key_object_get_handle(&dev_priv, device_privkey_id);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_get_handle failed res : %d", kss_status);
        return;
    }
#ifdef ONLY_MBEDTLS_TEST
#ifndef MBEDTLS_RANDOM_USE_SE
    ret = mbedtls_pk_parse_key(&client_key, (const unsigned char *)client_key_start, client_key_end - client_key_start, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
#else   // MBEDTLS_RANDOM_USE_SE
    ret = mbedtls_pk_parse_key(&client_key, (const unsigned char *)client_key_start, client_key_end - client_key_start, NULL, 0, kss_mbedtls_se_random, &rng_ctx);
#endif  // MBEDTLS_RANDOM_USE_SE
#endif // ONLY_MBEDTLS_TEST

    ////////////////////////////////////////////////////////////////////////
    //////////////////// device public key handle //////////////////////////
    ////////////////////////////////////////////////////////////////////////
    // keypair init
    kss_status = kss_key_object_init(&dev_pub, &keystore);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init failed res : %d", kss_status);
        return;
    }

    kss_status = kss_key_object_get_handle(&dev_pub, 0x0200);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_get_handle failed res : %d", kss_status);
        return;
    }

    
#ifdef ONLY_MBEDTLS_TEST_CERTFILE
#ifdef ESP_PLATFORM
    ret = mbedtls_x509_crt_parse(&client_cert, (const unsigned char *)client_cert_start, (client_cert_end - client_cert_start));    //저장된 cert 사용 시
#else   // ESP_PLATFORM
    if(load_cert_to_buffer("./certs/client.crt", &client_cert_start, &client_cert_end) != 0){
        printf("load_cert_to_buffer failed\n");
        return;
    }
#endif  // ESP_PLATFORM
#else   // ONLY_MBEDTLS_TEST_CERTFILE
    ////////////////////////////////////////////////////////////////////////
    //////////////////////// device cert handle ////////////////////////////
    ////////////////////////////////////////////////////////////////////////
    // keypair init
    kss_status = kss_key_object_init(&dev_cert, &keystore);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init failed res : %d", kss_status);
        return;
    }

    kss_status = kss_key_object_get_handle(&dev_cert, device_cert_id);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_get_handle failed res : %d", kss_status);
        return;
    }

    dataSize = 0;
    uint8_t aclient_cer[SIZE_CLIENT_CERTIFICATE];

    kss_status = kss_key_store_get_data(&keystore, &dev_cert, aclient_cer, &dataSize);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_get_data failed res : %d", kss_status);
        return;
    }

    ret = mbedtls_x509_crt_parse_der(&client_cert, (const unsigned char *)aclient_cer, sizeof(aclient_cer));
    if (ret < 0) {
        LOGE(TAG, " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int) -ret);
        return;
    }
#endif

    ////////////////////////////////////////////////////////////////////////
    //////////////////////////// CA cert handle ////////////////////////////
    ////////////////////////////////////////////////////////////////////////
    // CA object init
    kss_status = kss_key_object_init(&pub_obj, &keystore);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init failed res : %d", kss_status);
        return;
    }

    kss_status = kss_key_object_get_handle(&pub_obj, ca_public_id);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_get_handle failed res : %d", kss_status);
        return;
    } 

    ////////////////////////////////////////////////////////////////////////
    //////////////////////// Load the trusted CA////////////////////////////
    ////////////////////////////////////////////////////////////////////////
#ifndef ONLY_MBEDTLS_TEST_CERTFILE
#ifdef ESP_PLATFORM
#ifdef AWS_CA_CERT_ECC
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)root_cert_auth_ecc_start, (root_cert_auth_ecc_end - root_cert_auth_ecc_start) + null_size); 
#else   // AWS_CA_CERT_ECC
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)root_cert_auth_start, (root_cert_auth_end - root_cert_auth_start) + null_size); 
#endif  // AWS_CA_CERT_ECC
#else   // ESP_PLATFORM
#ifdef AWS_CA_CERT_ECC
    if(load_cert_to_buffer("./certs/root_cert_auth_ecc.crt", &root_cert_auth_start, &root_cert_auth_end) != 0){
        printf("load_cert_to_buffer failed\n");
        return;
    }
#else   // AWS_CA_CERT_ECC
    if(load_cert_to_buffer("./certs/root_cert_auth.crt", &root_cert_auth_start, &root_cert_auth_end) != 0){
        printf("load_cert_to_buffer failed\n");
        return;
    }
#endif  // AWS_CA_CERT_ECC
#endif  // ESP_PLATFORM
#else   // ONLY_MBEDTLS_TEST_CERTFILE
    dataSize = 0;
    uint8_t aCA_cer[SIZE_CLIENT_CERTIFICATE];

    LOGD(TAG, "CA Cert Get Data");
    kss_status = kss_key_store_get_data(&keystore, &pub_obj, aCA_cer, &dataSize);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_get_data failed res : %d", kss_status);
        return;
    }

    ret = mbedtls_x509_crt_parse_der(&cacert, (const unsigned char *)aCA_cer, sizeof(aCA_cer));
#endif
     if (ret < 0) {
        LOGE(TAG, " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int) -ret);
        return;
    }

#ifndef ONLY_MBEDTLS_TEST
    // SE 서명 검증 기능
    if(kss_mbedtls_verify_sign(&cacert.pk, &pub_obj) != 0){    //kss_mbedtls_verify_sign 이름 변경
        LOGE(TAG, "kss_mbedtls_verify_sign failed");
        return;
    }
    
    // SE 서명 기능
    if(kss_mbedtls_sign(&client_key, &dev_priv) != 0){    // kss_mbedtls_sign
        LOGE(TAG, "kss_mbedtls_sign failed");
    }
#endif
   
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
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
    ret = mbedtls_ssl_set_hostname(&ssl, AWS_IOT_ENDPOINT);
    if(ret != 0){
        LOGE(TAG, "mbedtls_ssl_set_hostname failed -0x%04X\n", -ret);
        return;
    }

    ret = mbedtls_net_connect(&net, AWS_IOT_ENDPOINT, AWS_IOT_PORT, MBEDTLS_NET_PROTO_TCP);
    if(ret != 0){
        LOGE(TAG, "mbedtls_net_connect failed -0x%04X\n", -ret);
        return;
    }
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
 
    // TLS handshake
    ret = mbedtls_ssl_handshake(&ssl);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        LOGE(TAG, "TLS handshake failed: -0x%04X - %s\n", ret, err_buf);
        return;
    }

    LOGI(TAG, "TLS handshake success\n");

    // MQTT 연결 및 메시지 전송
    ret = mqtt_send_connect(&ssl, MQTT_CLIENT_ID);
    if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        LOGE(TAG, "mqtt_send_connect failed: -0x%04X - %s\n", -ret, err_buf);
    } else {
        LOGI(TAG, "mqtt_send_connect success! Wrote %d bytes\n", ret);
    }

    //ret = mqtt_read_response(&ssl);
    unsigned char rst_buf[256] ={0,};
    ret = mqtt_read_response(&ssl, rst_buf, sizeof(rst_buf));
    if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        LOGE(TAG, "mqtt_read_response failed: -0x%04X - %s\n", -ret, err_buf);
    } else {
        kss_debug_showframe(TAG, rst_buf, ret);
        LOGI(TAG, "mqtt_read_response success! Wrote %d bytes\n", ret);
    }
    
    ret = mqtt_send_publish(&ssl, MQTT_TOPIC, MQTT_PAYLOAD);
    if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        LOGE(TAG, "mqtt_send_publish failed: -0x%04X - %s\n", -ret, err_buf);
    } else {
        LOGI(TAG, "mqtt_send_publish success! Wrote %d bytes\n", ret);
    }

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&net);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&client_cert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&client_key);
} 
