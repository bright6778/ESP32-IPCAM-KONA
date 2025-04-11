/////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2025 Kona I Co., Ltd.
// 
// All rights are reserved.
// Proprietary and confidential.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Any use is subject to an appropriate license granted by Kona I Co., Ltd..
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//! @file    kona_kss_kose_config.h
//! @brief   KSS SDK config module
/////////////////////////////////////////////////////////////////////////////

#ifndef __KSS_KOSE_CONFIG_H
#define __KSS_KOSE_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h>
#include <stdbool.h>

#define KSS_SESSION_MAX_CONTEXT_SIZE 100
#define CONNECT_SE_UART 1

#if CONNECT_SE_UART
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

#endif

#ifdef __cplusplus
}
#endif
#endif