/*
 * kona_se.h
 *
 *  Created on: May 4, 2018
 *      Author: GM Al Mamun
 */

#ifndef TSM_SDK_KONA_SE_H_
#define TSM_SDK_KONA_SE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "driver/gpio.h"
#include "driver/uart.h"
#include "driver/ledc.h"
#include "esp_err.h"
#include "esp_log.h"
#include "smartcard.h"  
//#ifdef __APPLE__
//#include <PCSC/winscard.h>
//#include <PCSC/wintypes.h>
//#else
// #include <PCSC/winscard.h>
#include "enums.h"
#include "debug.h"
//#endif
//#include "apdu.h"

#define MAX_APDU_RESPONSE_LENGTH 264
#define UART_DRIVER_ERROR "uart driver error"
/////////////////////////////////////////////////////////////////////////////
// Variables
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
// Struct
/////////////////////////////////////////////////////////////////////////////

/*typedef struct
{
    int se_uart_txd;
    int se_uart_rxd;
    int se_uart_rts;
    int se_uart_cts;
    uart_port_t se_uart_port_num;
    int se_uart_baud_rate;
    int se_uart_buff_size;
} kss_kose_uart_pin_t;

typedef struct
{
    kss_kose_uart_pin_t se_uart_pin;
    ledc_timer_config_t ledc_timer;
    ledc_channel_config_t ledc_channel;
} kss_kose_uart_ctx_t;*/

/////////////////////////////////////////////////////////////////////////////
// SE IO 핀 정의 (UART 통신 설정)
/////////////////////////////////////////////////////////////////////////////

#define SE_UART_TXD (7)   // TXD pin
#define SE_UART_RXD (6)   // RXD pin
#define SE_UART_RTS (-1)  // RTS pin
#define SE_UART_CTS (-1)  // CTS pin

#define SE_UART_PORT_NUM      (UART_NUM_1)
#define SE_UART_BAUD_RATE     (9600)
#define SE_UART_BUFF_SIZE    (1024)

/////////////////////////////////////////////////////////////////////////////
// CLK 핀 정의 (PWM 설정)
/////////////////////////////////////////////////////////////////////////////

#define SCR_PWM_CHANNEL   LEDC_CHANNEL_0
#define SCR_PWM_TIMER     LEDC_TIMER_0
#define SCR_PWM_OUTPUT_IO (8)                 // 사용할 GPIO 핀 번호 (5:ok, 8:ok, 9:fail)
#define SCR_PWM_FREQUENCY (3579545)           // PWM 주파수 (Hz)
#define SCR_PWM_DUTY_RES  LEDC_TIMER_1_BIT    // 1비트 해상도
#define SCR_PWM_DUTY      (2 - 1)             // 최대 듀티 사이클
/////////////////////////////////////////////////////////////////////////////
// Functions
/////////////////////////////////////////////////////////////////////////////

/*void smartcard_vcc_init(void);
void smartcard_vcc_ctrl(int on);
void smartcard_rst_init(void);
void smartcard_rst_ctrl(int ctrl);
//void smartcard_clk_init(kss_kose_uart_ctx_t kose_uart_init_config);
void smartcard_clk_init();
void smartcard_clk_ctrl(int ctrl);
//void smartcard_io_init(kss_kose_uart_ctx_t kose_uart_init_config);
void smartcard_io_init();
void smartcard_io_reinit(uint8_t fd);
void smartcard_activate(void);
void smartcard_deactivate(void);
void smartcard_warm_reset(void);
bool smartcard_transceive(uint8_t *sndbuf, int sndlen, uint8_t *rcvbuf, int *rcvlen);
bool smartcard_apdu(uint8_t *sndbuf, int sndlen, uint8_t *rcvbuf, int *rcvlen);
void smartcard_atr_parser(uint8_t atr[], int len);
void smartcard_test(void);
void smartcard_task(void *arg);
void smartcard_task_create(void);
bool smartcard_getATR(uint8_t *rcvbuf, int rcvlen);
bool smartcard_pps_exchange(uint8_t *rcvbuf, int rcvlen);*/
bool init_se(void);
void close_se(void);
/**
 * This method is used to Establish Smart Card Context, Select Smart Card Reader, and Connect with Smart Card
 */
//void init_se();

/**
 * This method is used to disconnect with Smart Card, free card reader and Release Smart Card Context.
 */
//void close_se();

/**
 * Before calling this method you must need to call @see init_se() and res_len initialized with zero(0).
 *
 * This method is used to transmit command into Smart Card and retrieve corresponding response data.
 *
 * @param apduCMD This parameter is actual apdu command that is transmit into smart card.
 * @param apduLen This parameter is length of apdu command.
 * @param response This is the response parameter that is the receive corresponding response apdu from smart card
 * @param res_len This parameter contain length of response apdu initial value must be set with zero(0)
 *
 * @return int This returns 0 or -1, if command execute success with response SW 9000 then return 0 otherwise -1
 */
//int send_command(unsigned char *apduCMD, int apduLen, unsigned char *response, int *res_len);

/**
 * This method is used to retrieve Secure Element ID (SEID) from Smart Card.
 *
 * @param se_id This parameter used to receive SEID from Smart Card.
 * @param se_id_len This returns the length of SEID.
 * @return int status of the access to SEID from card
 */
int get_se_id(char** se_id, int *se_id_len);
int get_cplc(char** cplc);
int is_applet_exist(unsigned char* aid, int len);

#endif /* TSM_SDK_KONA_SE_H_ */
