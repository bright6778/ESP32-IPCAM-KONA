/*
 *
 * Copyright 2025 KONA I
 * SPDX-License-Identifier: Apache-2.0
 */

  /** @file */
#ifdef __cplusplus
extern "C" {
#endif

#include "kss_kose_uart.h"
#include "smartcard.h"

static const char *TAG = "kss_kose_uart.c";

kss_kose_uart_ctx_t se_uart_init = {
    .se_uart_pin.se_uart_txd = SE_UART_TXD,
    .se_uart_pin.se_uart_rxd = SE_UART_RXD,
    .se_uart_pin.se_uart_rts = SE_UART_RTS,
    .se_uart_pin.se_uart_cts = SE_UART_CTS,
    .se_uart_pin.se_uart_port_num = UART_NUM_1,
    .se_uart_pin.se_uart_baud_rate = SE_UART_BAUD_RATE,
    .se_uart_pin.se_uart_buff_size = SE_UART_BUFF_SIZE,

    .ledc_timer.speed_mode = LEDC_LOW_SPEED_MODE,
    .ledc_timer.timer_num = SCR_PWM_TIMER,
    .ledc_timer.duty_resolution = SCR_PWM_DUTY_RES,
    .ledc_timer.freq_hz = SCR_PWM_FREQUENCY,
    .ledc_timer.clk_cfg = LEDC_AUTO_CLK,

    .ledc_channel.speed_mode = LEDC_LOW_SPEED_MODE,
    .ledc_channel.channel = SCR_PWM_CHANNEL,
    .ledc_channel.timer_sel = SCR_PWM_TIMER,
    .ledc_channel.intr_type = LEDC_INTR_DISABLE,
    .ledc_channel.gpio_num = SCR_PWM_OUTPUT_IO,
    .ledc_channel.duty = 1,
    .ledc_channel.hpoint = 0
};

/////////////////////////////////////////////////////////////////////////////
// Variables
/////////////////////////////////////////////////////////////////////////////
uint8_t *rcvbuf;
int rcvlen;

void set_se_uart_init_default(kss_kose_uart_ctx_t *se_uart_init){
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

bool kss_kose_uart_init(kss_kose_uart_ctx_t *kose_uart_init_config){
    bool ret = false;
    smartcard_vcc_init();
    smartcard_rst_init();
    smartcard_clk_init(*kose_uart_init_config);
    smartcard_io_init(*kose_uart_init_config);
    rcvbuf = (uint8_t *)malloc(512); // Loopback + ProcedureBytes + TPDU
    ret = smartcard_getATR(rcvbuf, rcvlen);
    if (ret == false){
        free(rcvbuf);
        rcvbuf = NULL;
        return ret;
    } 
    ret = smartcard_pps_exchange(rcvbuf, rcvlen);
    return ret;
}

void kss_kose_uart_close(){
    LOGD(TAG, "kss_kose_uart_close start");
    ledc_stop(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, 0);
    uart_driver_delete(UART_NUM_1);
    uart_set_pin(UART_NUM_1, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    if(rcvbuf != NULL){
        LOGD(TAG, "free");
        free(rcvbuf);
        rcvbuf = NULL;
    }  
}

smStatus_t kss_kose_uart_transceive(uint8_t *sndbuf, int sndlen, uint8_t *rcvbuf, int *rcvlen){
    bool bReturn = false;
    smStatus_t status = SM_NOT_OK;
    bReturn = smartcard_apdu(sndbuf, sndlen, rcvbuf, rcvlen);
    if(bReturn == true){
        uint8_t sw1 = rcvbuf[*rcvlen - 2];
        uint8_t sw2 = rcvbuf[*rcvlen - 1];
        status = (sw1 << 8) | sw2;
    }
    return status;
}

#ifdef __cplusplus
}
#endif