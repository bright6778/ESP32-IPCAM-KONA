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
#include "kona_kss_debug.h"
#include "tsm_sdk.h"
#include "menu_define.h"
#include "kss_sdk_api_test.h"
//#include "kona_se.h"

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
#define APDU_ENCRYPT_DECRYPT_CDATA_ENC  "Kose_API_EncryptData"
#define APDU_ENCRYPT_DECRYPT_CDATA_DEC  "Kose_API_DecryptData"
#define KEY_STORE_GET_DATA          "kss_key_store_get_data"
#define KEY_STORE_SET_KEY           "kss_key_store_set_key"
#define KEY_STORE_DATA              "kss_key_store_data"
#define MBEDTLS_VERIFY_SIGN         "kss_mbedtls_verify_sign"
#define SE_PROVISIONING             "se_provisioning"
#define AWS_IOT_DEMO                "aws_iot_demo_main"
#define RANDOM_GEN                  "kss_kose_rng"
#define GEN_CSR                     "gen_csr"
#define CHECK_SE                    "check_se"
#define REGISTER_SE                 "register_se"
#define REGISTER_DEVICE             "register_device"
#define ISSUE_APPLET                "issue_applet"
#define EXCHANGE_SERVICE_DATA       "exchange_service_data"
#define DELETE_APPLET               "delete_applet"
#define GSMCALLBACKRESPONSE         "gsmcallbackresponse"


//#define SE_ID								"8009069009064009061520"
#define SE_ID								"0290000290002400000005"
//#define CPLC								"81009809409105005200FFFFFFFFFFFFFFFF4092"
#define CPLC								"8100980940915343FE414021240A05300D304092"
#define BASE_URL							"http://220.72.230.41:2011/TSM_PROXY"
#define SE_ID_DUMMY_ISSUE_APPLET			"8982201311151721561F"
#define IMEI_DUMMY_ISSUE_APPLET				"353490061878118"
#define SERVICE_ID_DUMMY_ISSUE_APPLET 			"2A831A8CE0682424A1021200000016"
#define SERVICE_VERSION_DUMMY_ISSUE_APPLET 	"1.0.0"
#define CUSTOMER_ID_DUMMY_ISSUE_APPLET 		"konaone10@konai.com"
#define A_ID_DUMMY_ISSUE_APPLET 			"A0000000031010"
#define IMEI_DUMMY_REGISTER_SE 				"353490061878118"

void aws_iot_mbedtls_mqtt_test(kss_session_t *session);
int aws_iot_demo_main( int argc, char ** argv );
void se_provisioning(kss_session_t *session);
int gen_csr();
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
    printf(ANSI_COLOR_RESET);
    printf("//////////////////////////////////////////////////////////////////////////////////\n");
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " REBOOT " or " REBOOT_NUM, REBOOT);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " UART_INIT " or " UART_INIT_NUM, UART_INIT);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " UART_TRANSCEIVE " or " UART_TRANSCEIVE_NUM, UART_TRANSCEIVE);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " UART_CLOSE " or " UART_CLOSE_NUM, UART_CLOSE);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " SESSION_CREATE " or " SESSION_CREATE_NUM, SESSION_CREATE);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " SESSION_OPEN " or " SESSION_OPEN_NUM, SESSION_OPEN);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " SESSION_CLOSE " or " SESSION_CLOSE_NUM, SESSION_CLOSE);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " APDU_SELECT_AID " or " APDU_SELECT_AID_NUM, APDU_SELECT_AID);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " APDU_GET_RANDOM " or " APDU_GET_RANDOM_NUM, APDU_GET_RANDOM);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " APDU_STORE_DATA " or " APDU_STORE_DATA_NUM, APDU_STORE_DATA);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " APDU_PUT_KEY " or " APDU_PUT_KEY_NUM, APDU_PUT_KEY);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " APDU_ENCRYPT_DECRYPT_CDATA_ENC " or " APDU_ENCRYPT_DECRYPT_CDATA_ENC_NUM, APDU_ENCRYPT_DECRYPT_CDATA_ENC);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " APDU_ENCRYPT_DECRYPT_CDATA_DEC " or " APDU_ENCRYPT_DECRYPT_CDATA_DEC_NUM, APDU_ENCRYPT_DECRYPT_CDATA_DEC);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " APDU_GENERATEKEY " or " APDU_GENERATEKEY_NUM, APDU_GENERATEKEY);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " KEY_STORE_GET_DATA " or " KEY_STORE_GET_DATA_NUM, KEY_STORE_GET_DATA);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " KEY_STORE_SET_KEY " or " KEY_STORE_SET_KEY_NUM, KEY_STORE_SET_KEY);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " KEY_STORE_DATA " or " KEY_STORE_DATA_NUM, KEY_STORE_DATA);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " GENERATE_KEY " or " GENERATE_KEY_NUM, GENERATE_KEY);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " RANDOM_GEN " or " RANDOM_GEN_NUM, RANDOM_GEN);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " MBEDTLS_VERIFY_SIGN " or " MBEDTLS_VERIFY_SIGN_NUM, MBEDTLS_VERIFY_SIGN);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " AWS_IOT_DEMO " or " AWS_IOT_DEMO_NUM, AWS_IOT_DEMO);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " GEN_CSR " or " GEN_CSR_NUM, GEN_CSR);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " CHECK_SE " or " CHECK_SE_NUM, CHECK_SE);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " REGISTER_DEVICE " or " REGISTER_DEVICE_NUM, REGISTER_DEVICE);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " ISSUE_APPLET " or " ISSUE_APPLET_NUM, ISSUE_APPLET);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " EXCHANGE_SERVICE_DATA " or " EXCHANGE_SERVICE_DATA_NUM, EXCHANGE_SERVICE_DATA);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " DELETE_APPLET " or " DELETE_APPLET_NUM, DELETE_APPLET);
    printf("%-*s - %s\n", MENU_TEXT_SIZE, "CMD : " GSMCALLBACKRESPONSE " or " GSMCALLBACKRESPONSE_NUM, GSMCALLBACKRESPONSE);
    printf("//////////////////////////////////////////////////////////////////////////////////\n");

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
    smStatus_t status   = SM_NOT_OK; 

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

                if (strcmp((char*)buf, REBOOT) == 0 || strcmp((char*)buf, REBOOT_NUM) == 0) {
                    LOGI(TAG, "ESP32 재부팅!");
                    esp_restart();
                }
                else if (strcmp((char*)buf, UART_INIT) == 0 || strcmp((char*)buf, UART_INIT_NUM) == 0) {    // kss_kose_uart_init
                    LOGI(TAG, "Start %s", UART_INIT);
                    set_se_uart_init_default(&se_uart_init);
                    ret = kss_kose_uart_init(&se_uart_init);
                    LOGI(TAG, "%s return : %d", UART_INIT, ret);
                    LOGI(TAG, "End %s", UART_INIT);
                }
                else if (strcmp((char*)buf, UART_TRANSCEIVE) == 0 || strcmp((char*)buf, UART_TRANSCEIVE_NUM) == 0) {    // kss_kose_uart_transceive
                    LOGI(TAG, "Start %s", UART_TRANSCEIVE);
                    uint8_t *rcvbuf = (uint8_t *)malloc(512); // Loopback + ProcedureBytes + TPDU;
                    int rcvlen;
                    ret = kss_kose_uart_transceive((uint8_t *)"\x00\xa4\x04\x00\x01\xa0", 6, rcvbuf, &rcvlen);
                    LOGI(TAG, "%s return : %d", UART_TRANSCEIVE, ret);
                    LOGI(TAG, "End %s", UART_TRANSCEIVE);
                    free(rcvbuf);
                }
                else if (strcmp((char*)buf, UART_CLOSE) == 0 || strcmp((char*)buf, UART_CLOSE_NUM) == 0) {    // kss_kose_uart_close
                    LOGI(TAG, "Start %s", UART_CLOSE);
                    kss_kose_uart_close();
                    LOGI(TAG, "Start %s", UART_CLOSE);
                }
                else if (strcmp((char*)buf, SESSION_CREATE) == 0 || strcmp((char*)buf, SESSION_CREATE_NUM) == 0) {    // kss_kose_session_create
                    LOGI(TAG, "Start %s", SESSION_CREATE);
                    kStatus = kss_session_create(&session, kType_KSS_SecureElement, 0, kKSS_ConnectionType_Plain, connectionData);
                    if (kStatus_KSS_Success != kStatus) {
                        LOGE(TAG, "kss_kose_session_create failed");
                    }
                    LOGI(TAG, "%s return : %d", SESSION_CREATE, kStatus);
                    LOGI(TAG, "End %s", SESSION_CREATE);
                }
                else if (strcmp((char*)buf, SESSION_OPEN) == 0 || strcmp((char*)buf, SESSION_OPEN_NUM) == 0) {    // kss_kose_session_open
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
                else if (strcmp((char*)buf, SESSION_CLOSE) == 0 || strcmp((char*)buf, SESSION_CLOSE_NUM) == 0) {    // kss_kose_session_close
                    LOGI(TAG, "Start %s", SESSION_CLOSE);
                    kss_session_close(&session);
                    LOGI(TAG, "End %s", SESSION_CLOSE);
                }
                else if (strcmp((char*)buf, APDU_SELECT_AID) == 0 || strcmp((char*)buf, APDU_SELECT_AID_NUM) == 0) {    // SE Command - SELECT AID 
                    LOGI(TAG, "Start %s", APDU_SELECT_AID);
                    size_t recLen = 0;
                    Kose_API_Select(&kose_session->s_ctx, resbuf, &recLen);
                    LOGI(TAG, "End %s", APDU_SELECT_AID);
                }
                else if (strcmp((char*)buf, APDU_GET_RANDOM) == 0 || strcmp((char*)buf, APDU_GET_RANDOM_NUM) == 0) {    // SE Command - GET RANDOM
                    LOGI(TAG, "Start %s", APDU_GET_RANDOM);
                    size_t recLen = 0;
                    Kose_API_GetRandom(&kose_session->s_ctx, 16, resbuf, &recLen);
                    LOGI(TAG, "End %s", APDU_GET_RANDOM);
                }
                else if (strcmp((char*)buf, APDU_INITIALIZE_UPDATE) == 0 || strcmp((char*)buf, APDU_INITIALIZE_UPDATE_NUM) == 0) {    // SE Command - INITIALIZE UPDATE
                    LOGI(TAG, "Start %s", APDU_INITIALIZE_UPDATE);
                    size_t recLen = 0;
                    Kose_API_Initialize_Update(&kose_session->s_ctx, resbuf, &recLen, 0x0100, (uint8_t *)"\x01\x02\x03\x04\x05\x06\x07\x08");
                    LOGI(TAG, "End %s", APDU_INITIALIZE_UPDATE);
                }
                else if (strcmp((char*)buf, APDU_EXTERNAL_AUTHENTICATE) == 0 || strcmp((char*)buf, APDU_EXTERNAL_AUTHENTICATE_NUM) == 0) {    // SE Command - EXTERNAL AUTHENTICATE
                    LOGI(TAG, "Start %s", APDU_EXTERNAL_AUTHENTICATE);
                    kss_object_t *keyObj = NULL;   //지금은 미사용
                    Kose_API_External_Authenticate(&kose_session->s_ctx, keyObj, 0x00, (uint8_t *)"\x01\x02\x03\x04\x05\x06\x07\x08", (uint8_t *)"\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8");
                    LOGI(TAG, "End %s", APDU_EXTERNAL_AUTHENTICATE);
                }
                else if (strcmp((char*)buf, APDU_STORE_DATA) == 0 || strcmp((char*)buf, APDU_STORE_DATA_NUM) == 0) {    // SE Command - STORE DATA
                    test_KOSE_API_StoreData();
                }
                else if (strcmp((char*)buf, APDU_PUT_KEY) == 0 || strcmp((char*)buf, APDU_PUT_KEY_NUM) == 0) {    // SE Command - PUT KEY
                    LOGI(TAG, "Start %s", APDU_PUT_KEY);
                    Kose_API_PutKey(&kose_session->s_ctx, 0x0400, 0x003200, (uint8_t *)"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F", 16);
                    LOGI(TAG, "End %s", APDU_PUT_KEY);
                }
                else if (strcmp((char*)buf, APDU_ENCRYPT_DECRYPT_CDATA_ENC) == 0 || strcmp((char*)buf, APDU_ENCRYPT_DECRYPT_CDATA_ENC_NUM) == 0) {    // SE Command - ENCRYPT/DECRYPT CDATA
                    LOGI(TAG, "Start %s", APDU_ENCRYPT_DECRYPT_CDATA_ENC);
                    size_t recLen = 0;
                    Kose_API_EncryptData(&kose_session->s_ctx, 0x7788, kAlgorithm_KSS_AES_CBC, 
                        (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, 
                        (uint8_t *)"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F", 16, resbuf, &recLen);
                    kss_debug_showframe("Encrypt Data", resbuf, recLen);

                    Kose_API_EncryptData(&kose_session->s_ctx, 0x7788, kAlgorithm_KSS_AES_CBC, 
                        (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, 
                        resbuf, recLen, resbuf, &recLen);
                    kss_debug_showframe("Decrypt Data", resbuf, recLen);
                    LOGI(TAG, "End %s", APDU_ENCRYPT_DECRYPT_CDATA_ENC);
                }
                else if (strcmp((char*)buf, KEY_STORE_GET_DATA) == 0 || strcmp((char*)buf, KEY_STORE_GET_DATA_NUM) == 0) {    // kss_key_store_get_data
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
                else if (strcmp((char*)buf, KEY_STORE_SET_KEY) == 0 || strcmp((char*)buf, KEY_STORE_SET_KEY_NUM) == 0) {    // kss_key_store_set_key
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
                else if (strcmp((char*)buf, KEY_STORE_DATA) == 0 || strcmp((char*)buf, KEY_STORE_DATA_NUM) == 0) {    // kss_key_store_data
                    LOGI(TAG, "Start %s", KEY_STORE_DATA);
                    size_t dataSize = 710;
                    memset(&keystore, 0, sizeof(kss_key_store_t));

                    LOGI(TAG, "Start kss_key_store_context_init");
                    kStatus = kss_key_store_context_init(&keystore, &session);
                    if(kStatus != kStatus_KSS_Success){
                        LOGE(TAG, "kss_key_store_context_init failed res : %d", kStatus);
                        goto Exit;
                    }

                    LOGI(TAG, "Start kss_key_object_init");
                    kStatus = kss_key_object_init(&keyobject, &keystore);
                    if (kStatus != kStatus_KSS_Success) {
                        LOGE(TAG, "kss_key_object_init res : %d", kStatus);
                        goto Exit;
                    }

                    LOGI(TAG, "Start kss_key_object_allocate_handle");
                    kStatus = kss_key_object_allocate_handle(&keyobject, 0x0700, kKSS_KeyPart_Default, kKSS_CipherType_Binary, dataSize, 0x001032, kKeyObject_Mode_Persistent);
                    if (kStatus != kStatus_KSS_Success) {
                        LOGE(TAG, "kss_key_object_allocate_handle failed res : %d", kStatus);
                        goto Exit;
                    }

                    LOGI(TAG, "Start " KEY_STORE_DATA);
                    uint8_t objectData[710] = {0};
                    mempcpy(objectData, (uint8_t*)  "\x30\x82\x02\xc2\x30\x82\x01\xaa\xa0\x03\x02\x01\x02\x02\x14\x41"
                                                    "\xf7\x79\xba\xe7\x28\xe1\xc3\x88\xa7\xfc\x28\x16\xad\x64\x46\xf9"
                                                    "\xf1\x15\x0b\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
                                                    "\x05\x00\x30\x4d\x31\x4b\x30\x49\x06\x03\x55\x04\x0b\x0c\x42\x41"
                                                    "\x6d\x61\x7a\x6f\x6e\x20\x57\x65\x62\x20\x53\x65\x72\x76\x69\x63"
                                                    "\x65\x73\x20\x4f\x3d\x41\x6d\x61\x7a\x6f\x6e\x2e\x63\x6f\x6d\x20"
                                                    "\x49\x6e\x63\x2e\x20\x4c\x3d\x53\x65\x61\x74\x74\x6c\x65\x20\x53"
                                                    "\x54\x3d\x57\x61\x73\x68\x69\x6e\x67\x74\x6f\x6e\x20\x43\x3d\x55"
                                                    "\x53\x30\x1e\x17\x0d\x32\x35\x30\x35\x32\x36\x30\x32\x34\x35\x31"
                                                    "\x30\x5a\x17\x0d\x34\x39\x31\x32\x33\x31\x32\x33\x35\x39\x35\x39"
                                                    "\x5a\x30\x52\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x4b\x52"
                                                    "\x31\x13\x30\x11\x06\x03\x55\x04\x08\x0c\x0a\x53\x6f\x6d\x65\x2d"
                                                    "\x53\x74\x61\x74\x65\x31\x0e\x30\x0c\x06\x03\x55\x04\x0a\x0c\x05"
                                                    "\x4b\x6f\x6e\x61\x69\x31\x0e\x30\x0c\x06\x03\x55\x04\x0b\x0c\x05"
                                                    "\x4b\x6f\x6e\x61\x69\x31\x0e\x30\x0c\x06\x03\x55\x04\x03\x0c\x05"
                                                    "\x4b\x6f\x6e\x61\x69\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d"
                                                    "\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04"
                                                    "\x28\xf1\x67\x05\x63\x7d\x4d\x89\x20\x19\x72\xec\x1d\x49\x00\xe2"
                                                    "\x97\x49\xe1\xa8\xb4\xe9\xc2\xfb\x72\x2d\xbe\xf5\xd0\x70\x4c\x5d"
                                                    "\x2a\x58\x5e\xf2\x42\xcb\xf1\xf2\x8d\xb2\x9e\xd8\xe4\x5e\xc9\x4e"
                                                    "\xf9\xfc\xd0\xa2\x78\xf0\x34\xff\x36\x20\x6b\x48\xc7\x2d\xbb\x62"
                                                    "\xa3\x60\x30\x5e\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80"
                                                    "\x14\xe6\xd5\xbc\x49\xd5\xd1\x52\xfa\x62\xd7\x2b\xdc\x66\x59\xaf"
                                                    "\xa5\x77\x90\xeb\x59\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14"
                                                    "\x36\x44\xac\x2b\x94\xcd\x65\xc0\xf6\xdf\x8a\x8c\x20\x85\xdb\x79"
                                                    "\x42\xe5\xd4\x41\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02"
                                                    "\x30\x00\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02"
                                                    "\x07\x80\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05"
                                                    "\x00\x03\x82\x01\x01\x00\x11\x0b\x91\xd5\xf1\x57\x31\xfb\xbc\xfa"
                                                    "\x16\x3d\xbe\x21\xe6\xd0\x32\x34\xf9\x9f\x17\x2f\x07\x66\x0b\x06"
                                                    "\xba\x90\x9d\x43\xdb\x07\x88\xe6\x11\x27\xd6\x08\x10\xa9\xb4\x28"
                                                    "\xd1\xcf\x9e\xb8\x9c\x40\x16\x4f\x29\x64\x56\x71\x84\x85\x48\xad"
                                                    "\x84\xdc\xc2\xe2\x9b\x56\x25\x18\xf7\x7c\x6b\x61\x91\x68\xc2\xdb"
                                                    "\x85\x28\xc4\xfa\x05\xa5\xa6\xcd\x6a\x19\x66\xc8\x9b\x42\xcc\x1d"
                                                    "\xae\x7d\x1d\x0b\x4a\x39\xdb\xa1\xfd\x5b\xd5\xcf\xc7\xaa\xa3\x22"
                                                    "\x1d\x81\x61\x09\x69\xa9\x18\xb3\x53\xf7\xf5\xfb\x8b\x94\xb3\xa5"
                                                    "\x49\xae\x05\xe1\xc3\x43\x2c\x88\xab\x5c\x60\x0a\xef\xe1\x73\xed"
                                                    "\x1a\x28\xd0\x24\xae\x07\xef\x6d\x95\xe7\xc4\x26\xb5\xc1\x76\x8b"
                                                    "\xcf\x7b\xc2\xb8\x52\xc9\x78\xc3\xbf\x43\x4b\xa2\x38\x78\x60\x58"
                                                    "\x54\x94\x17\xf1\xcb\xe5\x1b\x1d\x94\x08\x4c\x91\xf0\xa1\x23\xe9"
                                                    "\xc1\x7f\xfe\x16\x23\xf0\x8b\x77\x6f\x9f\xbd\x5f\x19\x9e\x36\x65"
                                                    "\xd2\x47\x2e\xe2\x25\xa4\x83\xac\xab\x5c\xf1\xa0\x34\x05\xbb\xaa"
                                                    "\x4f\x7b\xaf\x1c\xa8\x3d\x6a\x28\x9c\xa2\x25\x10\xe9\x3b\x9d\x1b"
                                                    "\xe5\x80\x40\xc8\x7e\x88\x4f\x41\x6e\x12\x53\x88\x09\x80\x74\x70"
                                                    "\x13\xbe\xdb\x03\x55\xc3", dataSize);
                    kStatus = kss_key_store_data(&keystore, &keyobject, objectData, dataSize);
                    if (kStatus != kStatus_KSS_Success) {
                        LOGE(TAG, KEY_STORE_DATA " res : %d", kStatus);
                        goto Exit;
                    }
                    
                    kss_key_object_free(&keyobject);
                    kss_key_store_context_free(&keystore);
                    LOGI(TAG, "End %s", KEY_STORE_DATA);
                }
                else if (strcmp((char*)buf, GENERATE_KEY) == 0 || strcmp((char*)buf, GENERATE_KEY_NUM) == 0) {    // kss_key_store_generate_key
                    test_kss_key_store_generate_key();
                }
                else if (strcmp((char*)buf, API_KSS_SYMMETRIC_ENCRYPT) == 0 || strcmp((char*)buf, API_KSS_SYMMETRIC_ENCRYPT_NUM) == 0) {    // kss_symmetric_encrypt
                    test_kss_symmetric_encrypt();
                }
                else if (strcmp((char*)buf, RANDOM_GEN) == 0 || strcmp((char*)buf, RANDOM_GEN_NUM) == 0) {    // kss_kose_rng
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
                else if (strcmp((char*)buf, MBEDTLS_VERIFY_SIGN) == 0 || strcmp((char*)buf, MBEDTLS_VERIFY_SIGN_NUM) == 0) {    // kss_mbedtls_verify_sign
                    LOGI(TAG, "Start %s", MBEDTLS_VERIFY_SIGN);
                    LOGI(TAG, "End %s", MBEDTLS_VERIFY_SIGN);
                }
                else if (strcmp((char*)buf, SE_PROVISIONING) == 0 || strcmp((char*)buf, SE_PROVISIONING_NUM) == 0) {    // SE Provisioning
                    LOGI(TAG, "Start %s", SE_PROVISIONING);
                    se_provisioning(&session);
                    LOGI(TAG, "End %s", SE_PROVISIONING);
                }
                else if (strcmp((char*)buf, AWS_IOT_DEMO) == 0 || strcmp((char*)buf, AWS_IOT_DEMO_NUM) == 0) {    // aws_iot_demo_main
                    LOGI(TAG, "Start %s", AWS_IOT_DEMO);
                    //aws_iot_demo_main(0,NULL);    // AWS IoT Device Embedded C SDK
                    aws_iot_mbedtls_mqtt_test(&session);    // mbedTLS MQTT
                    LOGI(TAG, "End %s", AWS_IOT_DEMO);
                }
                else if (strcmp((char*)buf, GEN_CSR) == 0 || strcmp((char*)buf, GEN_CSR_NUM) == 0) {    // gen_csr
                    LOGI(TAG, "Start %s", GEN_CSR);
                    gen_csr(&session);
                    LOGI(TAG, "End %s", GEN_CSR);
                }else if (strcmp((char*)buf, CHECK_SE) == 0 || strcmp((char*)buf, CHECK_SE_NUM) == 0) {    // check_se
                    LOGI(TAG, "Start %s", CHECK_SE);
                    tsm_sdk_init();
                    init_se();

                    
                    char* imei = IMEI_DUMMY_ISSUE_APPLET;
                    /*char* pushToken = IMEI_DUMMY_ISSUE_APPLET;
                    char* cplc = CPLC;
                    char* service_id = SERVICE_ID_DUMMY_ISSUE_APPLET;
                    char* service_version = SERVICE_VERSION_DUMMY_ISSUE_APPLET;
                    char* customer_id = CUSTOMER_ID_DUMMY_ISSUE_APPLET;
                    char* a_id = A_ID_DUMMY_ISSUE_APPLET;
                    char* osName = "RTOS";
                    char* osVersion = "1.0.0";
                    char* msisdn = "+821199991111";
                    char* mnoName = "MONA";*/
                    SeIdType seIdType = CARD_UNIQUE_DATA;
                    SeType seType = SIM;
                    char* se_id = SE_ID;
                    //Push_Token_Type pushType = Xinjie;
                    SeDetail seList[1] = {
                        {se_id, seIdType, seType, false},
                };

	                int seListSize = sizeof(seList) / sizeof(seList[0]);

                    set_base_url(BASE_URL);
                        if(!check_se(imei, seList, seListSize)){
                            printf("error audit_se\n");
                        }
                    LOGI(TAG, "End %s", CHECK_SE);
                }else if (strcmp((char*)buf, "register_device") == 0 || strcmp((char*)buf, "14.1") == 0) { 
                    LOGI(TAG, "Start %s", REGISTER_DEVICE);
                    tsm_sdk_init();
                    init_se();

                    char* imei = IMEI_DUMMY_ISSUE_APPLET;
                    Push_Token_Type pushType = Xinjie;

                    set_base_url(BASE_URL);

                    if(!register_device_info(imei, pushType)){
                        printf("error REGISTER_DEVICE\n");
                    }

                    LOGI(TAG, "End %s", REGISTER_DEVICE);


                }else if (strcmp((char*)buf, "register_se") == 0 || strcmp((char*)buf, "15.1") == 0) { 
                    LOGI(TAG, "Start %s", REGISTER_SE);
                    tsm_sdk_init();
                    init_se();

                    //char* imei = IMEI_DUMMY_ISSUE_APPLET;
                    //char* cplc = CPLC;
                    SeType seType = SIM;
                    SeIdType seIdType = CARD_UNIQUE_DATA;
                    char* se_id = "4790D3218241907401020192568929995823";
                    SeDetail seList[1] = {
                        {se_id, seIdType, seType, false},
                    };
                    char* profileid = "2A831A8CE06864024100010101";
                    char* profilever = "1.1.2";
                    char* sep = "2A831A8CE068";
                    char* sdm = "2A831A8CE068";
                    char* sei = "2A831A8CE068";


	                int seListSize = sizeof(seList) / sizeof(seList[0]);

                    set_base_url(BASE_URL);

                    if(!register_se(seList, seListSize, profileid, profilever, sep, sdm, sei)){
                        printf("error REGISTER_SE\n");
                    }
                    LOGI(TAG, "End %s", REGISTER_SE);

                }else if (strcmp((char*)buf, "issue_applet") == 0 || strcmp((char*)buf, "16.1") == 0) { 
                    LOGI(TAG, "Start %s", ISSUE_APPLET);
                    LOGI(TAG, "End %s", ISSUE_APPLET);

                }else if (strcmp((char*)buf, "exchange_service_data") == 0 || strcmp((char*)buf, "17.1") == 0) { 
                    LOGI(TAG, "Start %s", EXCHANGE_SERVICE_DATA);
                    //exchange_service_data
                    LOGI(TAG, "End %s", EXCHANGE_SERVICE_DATA);

                }else if (strcmp((char*)buf, "delete_applet") == 0 || strcmp((char*)buf, "18.1") == 0) { 
                    LOGI(TAG, "Start %s", DELETE_APPLET);
                    LOGI(TAG, "End %s", DELETE_APPLET);

                }else if (strcmp((char*)buf, "gsmcallbackresponse") == 0 || strcmp((char*)buf, "19.1") == 0) { 
                    LOGI(TAG, "Start %s", GSMCALLBACKRESPONSE);
                    LOGI(TAG, "End %s", GSMCALLBACKRESPONSE);

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
Exit:
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

