/* Blink Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "demo_config.h"

#include "led_strip.h"
#include "sdkconfig.h"

#include "kona_kss_api.h"
#include "kose_APDU_impl.h"
#include "kose_tlv.h"
#include "kona_kss_kose_types.h"
#include <mbedtls/pk.h>
#include "kss_kose_mbedtls.h"
#include <esp_spiffs.h>
#include <scp03_Types.h>

#include "kss_kose_uart.h"
#include "debug.h"

///////////////////////////////////////////////////////////////
// Define
///////////////////////////////////////////////////////////////
#define UART_INIT                   "kss_kose_uart_init"
#define UART_TRANSCEIVE             "kss_kose_uart_transceive"
#define UART_CLOSE                  "kss_kose_uart_close"
#define SESSION_CREATE              "kss_kose_session_create"
#define SESSION_OPEN                "kss_kose_session_open"
#define SESSION_CLOSE               "kss_kose_session_close"
#define APDU_SELECT_AID             "Kose_API_Select"
#define APDU_GET_RANDOM             "Kose_API_GetRandom"
#define APDU_INITIALIZE_UPDATE      "Kose_API_Initialize_Update"
#define APDU_EXTERNAL_AUTHENTICATE  "KOSE_API_External_Authenticate"
#define APDU_STORE_DATA             "KOSE_API_StoreData"
#define APDU_PUT_KEY                "KOSE_API_PutKey"
#define APDU_SET_LOCK_STATE         "KOSE_API_SetLockState"
#define KEY_STORE_GET_DATA          "kss_key_store_get_data"
#define KEY_STORE_SET_KEY           "kss_key_store_set_key"
#define MBEDTLS_VERIFY_SIGN         "kss_mbedtls_verify_sign"
#define SE_PROVISIONING             "se_provisioning"
#define AWS_IOT_DEMO                "aws_iot_demo_main"
#define RANDOM_GEN                  "kss_kose_rng"
void aws_iot_mbedtls_mqtt_test(kss_session_t *session);
int aws_iot_demo_main( int argc, char ** argv );
void se_provisioning(kss_session_t *session);

static const char *TAG = "example";

/* Use project configuration menu (idf.py menuconfig) to choose the GPIO to blink,
   or you can edit the following line and set a number here.
*/
#define BLINK_GPIO CONFIG_BLINK_GPIO

static uint8_t s_led_state = 0;

#ifdef CONFIG_BLINK_LED_STRIP

static led_strip_handle_t led_strip;

static void blink_led(void)
{
    /* If the addressable LED is enabled */
    if (s_led_state) {
        /* Set the LED pixel using RGB from 0 (0%) to 255 (100%) for each color */
        led_strip_set_pixel(led_strip, 0, 16, 16, 16);
        /* Refresh the strip to send data */
        led_strip_refresh(led_strip);
    } else {
        /* Set all LED off to clear all pixels */
        led_strip_clear(led_strip);
    }
}

static void configure_led(void)
{
    LOGI(TAG, "Example configured to blink addressable LED!");
    /* LED strip initialization with the GPIO and pixels number*/
    led_strip_config_t strip_config = {
        .strip_gpio_num = BLINK_GPIO,
        .max_leds = 1, // at least one LED on board
    };
#if CONFIG_BLINK_LED_STRIP_BACKEND_RMT
    led_strip_rmt_config_t rmt_config = {
        .resolution_hz = 10 * 1000 * 1000, // 10MHz
        .flags.with_dma = false,
    };
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip));
#elif CONFIG_BLINK_LED_STRIP_BACKEND_SPI
    led_strip_spi_config_t spi_config = {
        .spi_bus = SPI2_HOST,
        .flags.with_dma = true,
    };
    ESP_ERROR_CHECK(led_strip_new_spi_device(&strip_config, &spi_config, &led_strip));
#else
#error "unsupported LED strip backend"
#endif
    /* Set all LED off to clear all pixels */
    led_strip_clear(led_strip);
}

#elif CONFIG_BLINK_LED_GPIO

static void blink_led(void)
{
    /* Set the GPIO level according to the state (LOW or HIGH)*/
    gpio_set_level(BLINK_GPIO, s_led_state);
}

static void configure_led(void)
{
    LOGI(TAG, "Example configured to blink GPIO LED!");
    gpio_reset_pin(BLINK_GPIO);
    /* Set the GPIO as a push/pull output */
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);
}

#else
#error "unsupported LED type"
#endif

#define BUF_SIZE 256
#define DATA_BUF_SIZE 2048
uint8_t buf[BUF_SIZE];
uint8_t resbuf[BUF_SIZE];
uint8_t bufData[DATA_BUF_SIZE];
int buf_index = 0;

void print_manu(){
    printf("//////////////////////////////////////////////////////////////////\n");
    printf("CMD : REBOOT                            - Board Reboot\n");
    printf("CMD : uart_init or 1.1                  - %s\n", UART_INIT);
    printf("CMD : uart_transceive or 1.2            - %s\n", UART_TRANSCEIVE);
    printf("CMD : uart_close or 1.3                 - %s\n", UART_CLOSE);
    printf("CMD : session_create or 2.1             - %s\n", SESSION_CREATE);
    printf("CMD : session_open or 2.2               - %s\n", SESSION_OPEN);
    printf("CMD : session_close or 2.3              - %s\n", SESSION_CLOSE);
    printf("CMD : com_select_aid or 3.1             - %s\n", APDU_SELECT_AID);
    printf("CMD : com_get_random or 3.2             - %s\n", APDU_GET_RANDOM);
    //printf("CMD : com_initialize_update or 3.3      - %s\n", APDU_INITIALIZE_UPDATE);
    //printf("CMD : com_external_authenticate or 3.4  - %s\n", APDU_EXTERNAL_AUTHENTICATE);
    printf("CMD : com_store_data or 3.5             - %s\n", APDU_STORE_DATA);
    printf("CMD : com_put_key or 3.6                - %s\n", APDU_PUT_KEY);
    printf("CMD : kss_key_store_get_data or 4.1     - %s\n", KEY_STORE_GET_DATA);
    printf("CMD : kss_key_store_set_key or 4.2      - %s\n", KEY_STORE_SET_KEY);
    printf("CMD : generate random 5.1               - %s\n", RANDOM_GEN);
    printf("CMD : mbedtls_verify_sign or 9.1        - %s\n", MBEDTLS_VERIFY_SIGN);
    //printf("CMD : se_provisioning or 10.1           - %s\n", SE_PROVISIONING);
    printf("CMD : aws_mqtt or 11.1                  - %s\n", AWS_IOT_DEMO);
    printf("//////////////////////////////////////////////////////////////////\n");
}

void set_se_uart_init(kss_kose_uart_ctx_t *se_uart_init){
    se_uart_init->se_uart_pin.se_uart_txd = SE_UART_TXD,
    se_uart_init->se_uart_pin.se_uart_rxd = SE_UART_RXD,
    se_uart_init->se_uart_pin.se_uart_rts = SE_UART_RTS,
    se_uart_init->se_uart_pin.se_uart_cts = SE_UART_CTS,
    se_uart_init->se_uart_pin.se_uart_port_num = UART_NUM_1,
    se_uart_init->se_uart_pin.se_uart_baud_rate = SE_UART_BAUD_RATE,
    se_uart_init->se_uart_pin.se_uart_buff_size = SE_UART_BUFF_SIZE,

    // LEDC 타이머 설정
    se_uart_init->ledc_timer.speed_mode = LEDC_LOW_SPEED_MODE;
    se_uart_init->ledc_timer.timer_num = SCR_PWM_TIMER;
    se_uart_init->ledc_timer.duty_resolution = SCR_PWM_DUTY_RES;
    se_uart_init->ledc_timer.freq_hz = SCR_PWM_FREQUENCY;
    se_uart_init->ledc_timer.clk_cfg = LEDC_AUTO_CLK;

    // LEDC 채널 설정
    se_uart_init->ledc_channel.speed_mode = LEDC_LOW_SPEED_MODE;
    se_uart_init->ledc_channel.channel = SCR_PWM_CHANNEL;
    se_uart_init->ledc_channel.timer_sel = SCR_PWM_TIMER;
    se_uart_init->ledc_channel.intr_type = LEDC_INTR_DISABLE;
    se_uart_init->ledc_channel.gpio_num = SCR_PWM_OUTPUT_IO;
    se_uart_init->ledc_channel.duty = 1;
    se_uart_init->ledc_channel.hpoint = 0;
}

static void showbuf(const char *title, const uint8_t *buf, int len)
{
    char tmpbuf[DATA_BUF_SIZE + 8];
    int count = 0;
    count = sprintf(&tmpbuf[count], "%s = [", title);
    for (int i = 0; i < len; i++) {
        count += sprintf(&tmpbuf[count], i ? " %02x" : "%02x", buf[i]);
        if (count >= DATA_BUF_SIZE) {
            LOGI(TAG, "%s", tmpbuf);
            count = 0;
        }
    }
    if (count > 0) {
        LOGI(TAG, "%s](%d)", tmpbuf, len);
    }
    else {
        LOGI(TAG, "](%d)", len);
    }
}

void command_task(void *arg)
{
    uint8_t byte;
    bool ret;
    kss_status_t kStatus = kStatus_KSS_Fail;

    // uart variables
    kss_kose_uart_ctx_t se_uart_init;
    SE_Connect_Ctx_t se_conn_ctx;
                    
    // session variables
    kss_session_t session;
    kss_kose_session_t *kose_session;
    memset(&session, 0, sizeof(kss_session_t));
    void *connectionData = NULL;
    kss_key_store_t keystore;
    kss_object_t keyobject; 
    
    while (1) {
        int len = uart_read_bytes(UART_NUM_0, &byte, 1, 100 / portTICK_PERIOD_MS);

        if (len > 0) {
            if (byte == '\r' || byte == '\n') {
                buf[buf_index] = '\0';
                printf("\n>> 명령 수신: %s\n", buf);

                if (strcmp((char*)buf, "REBOOT") == 0) {
                    LOGI(TAG, "ESP32 재부팅!");
                    esp_restart();
                }
                else if (strcmp((char*)buf, "uart_init") == 0 || strcmp((char*)buf, "1.1") == 0) {    // kss_kose_uart_init
                    LOGI(TAG, "Start %s", UART_INIT);
                    set_se_uart_init_default(&se_uart_init);
                    ret = kss_kose_uart_init(&se_uart_init);
                    LOGI(TAG, "%s return : %d", UART_INIT, ret);
                    LOGI(TAG, "End %s", UART_INIT);
                }
                else if (strcmp((char*)buf, "uart_transceive") == 0 || strcmp((char*)buf, "1.2") == 0) {    // kss_kose_uart_transceive
                    LOGI(TAG, "Start %s", UART_TRANSCEIVE);
                    uint8_t *rcvbuf = (uint8_t *)malloc(512); // Loopback + ProcedureBytes + TPDU;
                    int rcvlen;
                    ret = kss_kose_uart_transceive((uint8_t *)"\x00\xa4\x04\x00\x01\xa0", 6, rcvbuf, &rcvlen);
                    LOGI(TAG, "%s return : %d", UART_TRANSCEIVE, ret);
                    LOGI(TAG, "End %s", UART_TRANSCEIVE);
                    free(rcvbuf);
                }
                else if (strcmp((char*)buf, "uart_close") == 0 || strcmp((char*)buf, "1.3") == 0) {    // kss_kose_uart_close
                    LOGI(TAG, "Start %s", UART_CLOSE);
                    kss_kose_uart_close();
                    LOGI(TAG, "Start %s", UART_CLOSE);
                }
                else if (strcmp((char*)buf, "session_create") == 0 || strcmp((char*)buf, "2.1") == 0) {    // kss_kose_session_create
                    LOGI(TAG, "Start %s", SESSION_CREATE);
                    kStatus = kss_session_create(&session, kType_KSS_SecureElement, 0, kKSS_ConnectionType_Plain, connectionData);
                    if (kStatus_KSS_Success != kStatus) {
                        LOGE(TAG, "kss_kose_session_create failed");
                    }
                    LOGI(TAG, "%s return : %d", SESSION_CREATE, kStatus);
                    LOGI(TAG, "End %s", SESSION_CREATE);
                }
                else if (strcmp((char*)buf, "session_open") == 0 || strcmp((char*)buf, "2.2") == 0) {    // kss_kose_session_open
                    LOGI(TAG, "Start %s", SESSION_OPEN);
                    set_se_uart_init_default(&se_uart_init);
                    se_conn_ctx.connType = kType_SE_Conn_Type_UART;
                    se_conn_ctx.conn_ctx = &se_uart_init;
                    connectionData = &se_conn_ctx;
                    kStatus = kss_session_open(&session, kType_KSS_SecureElement, 0, kKSS_ConnectionType_Plain, connectionData);
                    if (kStatus_KSS_Success != kStatus) {
                        LOGE(TAG, "kss_kose_session_open failed res : %d", kStatus);
                    }
                    kose_session = (kss_kose_session_t*)&session;
                    LOGI(TAG, "%s return : %d", SESSION_OPEN, kStatus);
                    LOGI(TAG, "End %s", SESSION_OPEN);
                }
                else if (strcmp((char*)buf, "session_close") == 0 || strcmp((char*)buf, "2.3") == 0) {    // kss_kose_session_close
                    LOGI(TAG, "Start %s", SESSION_CLOSE);
                    kss_session_close(&session);
                    LOGI(TAG, "End %s", SESSION_CLOSE);
                }
                else if (strcmp((char*)buf, "com_select_aid") == 0 || strcmp((char*)buf, "3.1") == 0) {    // SE Command - SELECT AID 
                    LOGI(TAG, "Start %s", APDU_SELECT_AID);
                    size_t recLen = 0;
                    Kose_API_Select(&kose_session->s_ctx, resbuf, &recLen);
                    LOGI(TAG, "End %s", APDU_SELECT_AID);
                }
                else if (strcmp((char*)buf, "com_get_random") == 0 || strcmp((char*)buf, "3.2") == 0) {    // SE Command - GET RANDOM
                    LOGI(TAG, "Start %s", APDU_GET_RANDOM);
                    size_t recLen = 0;
                    Kose_API_GetRandom(&kose_session->s_ctx, 16, resbuf, &recLen);
                    LOGI(TAG, "End %s", APDU_GET_RANDOM);
                }
                else if (strcmp((char*)buf, "com_initialize_update") == 0 || strcmp((char*)buf, "3.3") == 0) {    // SE Command - INITIALIZE UPDATE
                    LOGI(TAG, "Start %s", APDU_INITIALIZE_UPDATE);
                    size_t recLen = 0;
                    Kose_API_Initialize_Update(&kose_session->s_ctx, resbuf, &recLen, 0x0100, (uint8_t *)"\x01\x02\x03\x04\x05\x06\x07\x08");
                    LOGI(TAG, "End %s", APDU_INITIALIZE_UPDATE);
                }
                else if (strcmp((char*)buf, "com_external_autnenticate") == 0 || strcmp((char*)buf, "3.4") == 0) {    // SE Command - EXTERNAL AUTHENTICATE
                    LOGI(TAG, "Start %s", APDU_EXTERNAL_AUTHENTICATE);
                    kss_object_t *keyObj = NULL;   //지금은 미사용
                    Kose_API_External_Authenticate(&kose_session->s_ctx, keyObj, 0x00, (uint8_t *)"\x01\x02\x03\x04\x05\x06\x07\x08", (uint8_t *)"\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8");
                    LOGI(TAG, "End %s", APDU_EXTERNAL_AUTHENTICATE);
                }
                else if (strcmp((char*)buf, "com_store_data") == 0 || strcmp((char*)buf, "3.5") == 0) {    // SE Command - STORE DATA
                    LOGI(TAG, "Start %s", APDU_STORE_DATA);
                    uint8_t objectData[] = {0x30, 0x82, 0x02, 0xC2, 0x30, 0x82, 0x01, 0xAA, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x41,
                                        0xF7, 0x79, 0xBA, 0xE7, 0x28, 0xE1, 0xC3, 0x88, 0xA7, 0xFC, 0x28, 0x16, 0xAD, 0x64, 0x46, 0xF9,
                                        0xF1, 0x15, 0x0B, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
                                        0x05, 0x00, 0x30, 0x4D, 0x31, 0x4B, 0x30, 0x49, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x42, 0x41,
                                        0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x20, 0x57, 0x65, 0x62, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
                                        0x65, 0x73, 0x20, 0x4F, 0x3D, 0x41, 0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x2E, 0x63, 0x6F, 0x6D, 0x20,
                                        0x49, 0x6E, 0x63, 0x2E, 0x20, 0x4C, 0x3D, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6C, 0x65, 0x20, 0x53,
                                        0x54, 0x3D, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x20, 0x43, 0x3D, 0x55,
                                        0x53, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x35, 0x32, 0x36, 0x30, 0x32, 0x34, 0x35, 0x31,
                                        0x30, 0x5A, 0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
                                        0x5A, 0x30, 0x52, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4B, 0x52,
                                        0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D,
                                        0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x05,
                                        0x4B, 0x6F, 0x6E, 0x61, 0x69, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x05,
                                        0x4B, 0x6F, 0x6E, 0x61, 0x69, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x05};
                    Kose_API_StoreData(&kose_session->s_ctx, 0x0700, 0x001032, 0x00, 0x00, objectData, sizeof(objectData));
                    LOGI(TAG, "End %s", APDU_STORE_DATA);
                }
                else if (strcmp((char*)buf, "com_put_key") == 0 || strcmp((char*)buf, "3.6") == 0) {    // SE Command - PUT KEY
                    LOGI(TAG, "Start %s", APDU_PUT_KEY);
                    Kose_API_PutKey(&kose_session->s_ctx, 0x7788, 0x010203, (uint8_t *)"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F", 16);
                    LOGI(TAG, "End %s", APDU_PUT_KEY);
                }
                else if (strcmp((char*)buf, "kss_key_store_get_data") == 0 || strcmp((char*)buf, "4.1") == 0) {    // kss_key_store_get_data
                    LOGI(TAG, "Start %s", KEY_STORE_GET_DATA);

                    size_t dataSize = 713;
                    memset(&keystore, 0, sizeof(kss_key_store_t));

                    LOGI(TAG, "Start kss_key_store_context_init");
                    kStatus = kss_key_store_context_init(&keystore, &session);
                    if(kStatus != kStatus_KSS_Success){
                        LOGE(TAG, "kss_key_store_context_init failed res : %d", kStatus);
                    }

                    LOGI(TAG, "Start kss_key_object_init");
                    kStatus = kss_key_object_init(&keyobject, &keystore);
                    if (kStatus != kStatus_KSS_Success) {
                        LOGE(TAG, "kss_key_object_init res : %d", kStatus);
                    }

                    LOGI(TAG, "Start kss_key_object_allocate_handle");
                    kStatus = kss_key_object_allocate_handle(&keyobject, 0x0700, kKSS_KeyPart_Default, kKSS_CipherType_EC_NIST_P, dataSize, 0x001032, kKeyObject_Mode_Persistent);
                    if (kStatus != kStatus_KSS_Success) {
                        LOGE(TAG, "kss_key_object_allocate_handle failed res : %d", kStatus);
                    }

                    LOGI(TAG, "Start kss_key_store_get_data");
                    kStatus = kss_key_store_get_data(&keystore, &keyobject, bufData, &dataSize);
                    if (kStatus != kStatus_KSS_Success) {
                        LOGE(TAG, "kss_key_store_get_data res : %d", kStatus);
                    }
                    showbuf("kss_key_store_get_data", bufData, dataSize);
                    LOGI(TAG, "End %s", KEY_STORE_GET_DATA);

                    kss_key_object_free(&keyobject);
                    kss_key_store_context_free(&keystore);
                }
                else if (strcmp((char*)buf, "kss_key_store_set_key") == 0 || strcmp((char*)buf, "4.2") == 0) {    // kss_key_store_set_key
                    LOGI(TAG, "Start %s", KEY_STORE_SET_KEY);
                    size_t dataSize = 65;
                    memset(&keystore, 0, sizeof(kss_key_store_t));

                    LOGI(TAG, "Start kss_key_store_context_init");
                    kStatus = kss_key_store_context_init(&keystore, &session);
                    if(kStatus != kStatus_KSS_Success){
                        LOGE(TAG, "kss_key_store_context_init failed res : %d", kStatus);
                    }

                    LOGI(TAG, "Start kss_key_object_init");
                    kStatus = kss_key_object_init(&keyobject, &keystore);
                    if (kStatus != kStatus_KSS_Success) {
                        LOGE(TAG, "kss_key_object_init res : %d", kStatus);
                    }

                    LOGI(TAG, "Start kss_key_object_allocate_handle");
                    kStatus = kss_key_object_allocate_handle(&keyobject, 0x0200, kKSS_KeyPart_Public, kKSS_CipherType_EC_NIST_P, dataSize, 0x100000, kKeyObject_Mode_Persistent);
                    if (kStatus != kStatus_KSS_Success) {
                        LOGE(TAG, "kss_key_object_allocate_handle failed res : %d", kStatus);
                    }

                    LOGI(TAG, "Start kss_key_store_set_key");
                    uint8_t client_pub_key[65] = {0};
                    mempcpy(client_pub_key, (uint8_t*)"\x04\x28\xf1\x67\x05\x63\x7d\x4d\x89\x20\x19\x72\xec\x1d\x49\x00\xe2"
                                      "\x97\x49\xe1\xa8\xb4\xe9\xc2\xfb\x72\x2d\xbe\xf5\xd0\x70\x4c\x5d"
                                      "\x2a\x58\x5e\xf2\x42\xcb\xf1\xf2\x8d\xb2\x9e\xd8\xe4\x5e\xc9\x4e"
                                      "\xf9\xfc\xd0\xa2\x78\xf0\x34\xff\x36\x20\x6b\x48\xc7\x2d\xbb\x62", dataSize);
                    kStatus = kss_key_store_set_key(&keystore, &keyobject, client_pub_key, dataSize, 256, NULL, 0);
                    if (kStatus != kStatus_KSS_Success) {
                        LOGE(TAG, "kss_key_store_set_key res : %d", kStatus);
                    }

                    kss_key_object_free(&keyobject);
                    kss_key_store_context_free(&keystore);
                    LOGI(TAG, "End %s", KEY_STORE_SET_KEY);
                }
                else if (strcmp((char*)buf, "generate_random") == 0 || strcmp((char*)buf, "5.1") == 0) {    // kss_kose_rng
                    LOGI(TAG, "Start %s", RANDOM_GEN);
                    uint8_t random_data[32] = {0}; 
                    int dataLen = 32;
                    kss_rng_context_t rng_ctx;
                    
                    kStatus = kss_rng_context_init(&rng_ctx, &session);
                    kStatus = kss_rng_get_random(&rng_ctx, random_data, dataLen);     

                    if (kStatus_KSS_Success != kStatus) {
                        LOGE(TAG, "kss_kose_rng failed");
                    }
                    LOGI(TAG, "%s return : %d", RANDOM_GEN, kStatus);
                    LOGI(TAG, "End %s", RANDOM_GEN);
                }
                else if (strcmp((char*)buf, "mbedtls_verify_sign") == 0 || strcmp((char*)buf, "9.1") == 0) {    // kss_mbedtls_verify_sign
                    LOGI(TAG, "Start %s", MBEDTLS_VERIFY_SIGN);
                    LOGI(TAG, "End %s", MBEDTLS_VERIFY_SIGN);
                }
                else if (strcmp((char*)buf, "se_provisioning") == 0 || strcmp((char*)buf, "10.1") == 0) {    // SE Provisioning
                    LOGI(TAG, "Start %s", SE_PROVISIONING);
                    se_provisioning(&session);
                    LOGI(TAG, "End %s", SE_PROVISIONING);
                }
                else if (strcmp((char*)buf, "aws_mqtt") == 0 || strcmp((char*)buf, "11.1") == 0) {    // aws_iot_demo_main
                    LOGI(TAG, "Start %s", AWS_IOT_DEMO);
                    //aws_iot_demo_main(0,NULL);    // AWS IoT Device Embedded C SDK
                    aws_iot_mbedtls_mqtt_test(&session);    // mbedTLS MQTT
                    LOGI(TAG, "End %s", AWS_IOT_DEMO);
                }
                print_manu();

                buf_index = 0;
                memset(buf, 0, BUF_SIZE);
            } else {
                if (buf_index < BUF_SIZE - 1) {
                    buf[buf_index++] = byte;
                    printf("%c", byte);  // Echo
                    fflush(stdout);
                }
            }
        }
    }
}

void command_task_create(void)
{
    xTaskCreate(command_task, "command_task", 16384, NULL, 1, NULL);
}

void app_main(void)
{

    // 1. UART 설정
    const uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };

    uart_param_config(UART_NUM_0, &uart_config);

    // 2. 드라이버 설치
    uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0);

    /* Configure the peripheral according to the LED type */
    configure_led();
    command_task_create();
    
    /* Initialize NVS partition */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* NVS partition was truncated
        * and needs to be erased */
        ESP_ERROR_CHECK(nvs_flash_erase());

        /* Retry nvs_flash_init */
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
    * Read "Establishing Wi-Fi or Ethernet Connection" section in
    * examples/protocols/README.md for more information about this function.
    */
    ESP_ERROR_CHECK(example_connect());
    
    print_manu();

    while (1) {
        //LOGI(TAG, "Turning the LED %s!", s_led_state == true ? "ON" : "OFF");
        blink_led();
        /* Toggle the LED state */
        s_led_state = !s_led_state;

        vTaskDelay(CONFIG_BLINK_PERIOD / portTICK_PERIOD_MS);
    }
}

