/////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2025 Kona I Co., Ltd.
// 
// All rights are reserved.
// Proprietary and confidential.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Any use is subject to an appropriate license granted by Kona I Co., Ltd..
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//! @file    kss_kose_uart.h
//! @brief   UART module
/////////////////////////////////////////////////////////////////////////////

#ifndef __KSS_KOSE_UART_H
#define __KSS_KOSE_UART_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "kona_kss_kose_config.h"
#include "smartcard.h"

void set_se_uart_init_default(kss_kose_uart_ctx_t *se_uart_init);
bool kss_kose_uart_init(kss_kose_uart_ctx_t *kose_uart_init_config);
void kss_kose_uart_close();
bool kss_kose_uart_transceive(uint8_t *sndbuf, int sndlen, uint8_t *rcvbuf, int *rcvlen);

#if defined(__cplusplus)
}
#endif

#endif