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
#include "esp_log.h"
#include "led_strip.h"
#include "sdkconfig.h"

#include "kona_kss_api.h"
//#include "kss_kose_uart.h"
//#include "smartcard.h"

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
    ESP_LOGI(TAG, "Example configured to blink addressable LED!");
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
    ESP_LOGI(TAG, "Example configured to blink GPIO LED!");
    gpio_reset_pin(BLINK_GPIO);
    /* Set the GPIO as a push/pull output */
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);
}

#else
#error "unsupported LED type"
#endif

#define BUF_SIZE 128
uint8_t buf[BUF_SIZE];
int buf_index = 0;

void print_manu(){
    printf("//////////////////////////////////////////////////////////////////\n");
    printf("CMD : REBOOT                    - Board Reboot\n");
    printf("CMD : uart_init or 1.1          - kss_kose_uart_init()\n");
    printf("CMD : uart_transceive or 1.2    - kss_kose_uart_transceive()\n");
    printf("CMD : uart_close or 1.3         - kss_kose_uart_close()\n");
    printf("CMD : session_create or 2.1     - kss_kose_session_create()\n");
    printf("CMD : session_open or 2.2       - kss_kose_session_open()\n");
    printf("CMD : session_close or 2.3      - kss_kose_session_close()\n");
    printf("CMD : session_delete or 2.4     - kss_kose_session_delete()\n");
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

void set_session_variables_dafault(kss_kose_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData){
}

void uart_command_task(void *arg)
{
    uint8_t byte;
    bool ret;

    // uart variables
    kss_kose_uart_ctx_t se_uart_init;

    // session variables
    kss_kose_session_t *session = NULL;
    kss_type_t subsystem = kType_KSS_mbedTLS;
    uint32_t application_id = 0;
    kss_connection_type_t connection_type = kKSS_ConnectionType_Plain;
    void *connectionData = NULL;
    
    while (1) {
        int len = uart_read_bytes(UART_NUM_0, &byte, 1, 100 / portTICK_PERIOD_MS);

        if (len > 0) {
            if (byte == '\r' || byte == '\n') {
                buf[buf_index] = '\0';
                printf("\n>> 명령 수신: %s\n", buf);

                if (strcmp((char*)buf, "REBOOT") == 0) {
                    ESP_LOGI(TAG, "ESP32 재부팅!");
                    esp_restart();
                }
                else if (strcmp((char*)buf, "uart_init") == 0 || strcmp((char*)buf, "1.1") == 0) {    // kss_kose_uart_init
                    ESP_LOGI(TAG, "Start kss_kose_uart_init");
                    set_se_uart_init(&se_uart_init);
                    ret = kss_kose_uart_init(se_uart_init);
                    ESP_LOGI(TAG, "kss_kose_uart_init return : %d", ret);
                    ESP_LOGI(TAG, "End kss_kose_uart_init");
                }
                else if (strcmp((char*)buf, "uart_transceive") == 0 || strcmp((char*)buf, "1.2") == 0) {    // kss_kose_uart_transceive
                    ESP_LOGI(TAG, "Start kss_kose_uart_transceive");
                    uint8_t *rcvbuf = (uint8_t *)malloc(512); // Loopback + ProcedureBytes + TPDU;
                    int rcvlen;
                    ret = kss_kose_uart_transceive((uint8_t *)"\x00\xa4\x04\x00\x01\xa0", 6, rcvbuf, &rcvlen);
                    ESP_LOGI(TAG, "kss_kose_uart_transceive return : %d", ret);
                    ESP_LOGI(TAG, "End kss_kose_uart_transceive");
                    free(rcvbuf);
                }
                else if (strcmp((char*)buf, "uart_close") == 0 || strcmp((char*)buf, "1.3") == 0) {    // kss_kose_uart_close
                    ESP_LOGI(TAG, "Start kss_kose_uart_close");
                    kss_kose_uart_close();
                    ESP_LOGI(TAG, "Start kss_kose_uart_close");
                }
                else if (strcmp((char*)buf, "session_create") == 0 || strcmp((char*)buf, "2.1") == 0) {    // kss_kose_session_create
                    ESP_LOGI(TAG, "Start kss_kose_session_create");
                    ret = kss_kose_session_create(session, subsystem, application_id, connection_type, connectionData);
                    ESP_LOGI(TAG, "kss_kose_session_create return : %d", ret);
                    ESP_LOGI(TAG, "End kss_kose_session_create");
                }
                else if (strcmp((char*)buf, "session_open") == 0 || strcmp((char*)buf, "2.2") == 0) {    // kss_kose_session_open
                    session->s_ctx.conn_ctx = &se_uart_init;
                    ESP_LOGI(TAG, "Start kss_kose_session_open");
                    ret = kss_kose_session_open(session, subsystem, application_id, connection_type, connectionData);
                    ESP_LOGI(TAG, "kss_kose_session_open return : %d", ret);
                    ESP_LOGI(TAG, "End kss_kose_session_open");
                }
                else if (strcmp((char*)buf, "session_close") == 0 || strcmp((char*)buf, "2.3") == 0) {    // kss_kose_session_close
                    ESP_LOGI(TAG, "Start kss_kose_session_close");
                    kss_kose_session_close(session);
                    ESP_LOGI(TAG, "End kss_kose_session_close");
                }
                else if (strcmp((char*)buf, "session_delete") == 0 || strcmp((char*)buf, "2.4") == 0) {    // kss_kose_session_delete
                    ESP_LOGI(TAG, "Start kss_kose_session_delete");
                    ESP_LOGI(TAG, "End kss_kose_session_delete");
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

void uart_command_task_create(void)
{
    xTaskCreate(uart_command_task, "uart_command_task", 4096, NULL, 1, NULL);
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
    uart_command_task_create();
    //smartcard_task_create();
    
    print_manu();

    while (1) {
        //ESP_LOGI(TAG, "Turning the LED %s!", s_led_state == true ? "ON" : "OFF");
        blink_led();
        /* Toggle the LED state */
        s_led_state = !s_led_state;

        vTaskDelay(CONFIG_BLINK_PERIOD / portTICK_PERIOD_MS);
    }
}

