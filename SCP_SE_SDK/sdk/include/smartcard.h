/////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2019 Kona I Co., Ltd.
// 
// All rights are reserved.
// Proprietary and confidential.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Any use is subject to an appropriate license granted by Kona I Co., Ltd..
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//! @file    smartcard.h
//! @brief   Smartcard processing module
/////////////////////////////////////////////////////////////////////////////

#ifndef __SMARTCARD_H
#define __SMARTCARD_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "driver/gpio.h"
#include "driver/uart.h"
#include "driver/ledc.h"
#include "debug.h"

#define UART_DRIVER_ERROR "uart driver error"
/////////////////////////////////////////////////////////////////////////////
// Variables
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
// Struct
/////////////////////////////////////////////////////////////////////////////

typedef struct
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
} kss_kose_uart_ctx_t;

/////////////////////////////////////////////////////////////////////////////
// Functions
/////////////////////////////////////////////////////////////////////////////

void smartcard_vcc_init(void);
void smartcard_vcc_ctrl(int on);
void smartcard_rst_init(void);
void smartcard_rst_ctrl(int ctrl);
void smartcard_clk_init(kss_kose_uart_ctx_t kose_uart_init_config);
void smartcard_clk_ctrl(int ctrl);
void smartcard_io_init(kss_kose_uart_ctx_t kose_uart_init_config);
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
bool smartcard_pps_exchange(uint8_t *rcvbuf, int rcvlen);



#endif // __SMARTCARD_H
