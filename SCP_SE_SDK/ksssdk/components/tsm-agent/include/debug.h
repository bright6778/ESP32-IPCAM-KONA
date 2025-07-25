/////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2025 Kona I Co., Ltd.
// 
// All rights are reserved.
// Proprietary and confidential.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Any use is subject to an appropriate license granted by Kona I Co., Ltd..
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//! @file    debug.h
//! @brief   디버그 모듈
/////////////////////////////////////////////////////////////////////////////

#ifndef __DEBUG_H
#define __DEBUG_H



/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

#define debug_getchar0   getchar

#include <stdint.h>



/////////////////////////////////////////////////////////////////////////////
// Functions
/////////////////////////////////////////////////////////////////////////////


void debug_set_flag_debug(char flag);
void debug_printf(char *fmt, ...);
void debug_puts(char *str);
void debug_putc(char ch);
void debug_showframe(char title[], uint8_t buff[], int len);
void debug_showframe2(char *title, uint8_t *buff, int len, int maxlen);
void debug_showframe3(char title[], uint8_t buff[], int len);
void debug_showhextable(unsigned addr, uint8_t *buff, int len);
int debug_getchar0(void);

//static void debug_dumpbyte(unsigned addr, unsigned count);
//static void debug_dumphalf(unsigned addr, unsigned count);
//static void debug_dumpword(unsigned addr, unsigned count);
//static void debug_setbyte(unsigned addr, uint8_t value);
//static void debug_sethalf(unsigned addr, uint16_t value);
//static void debug_setword(unsigned addr, unsigned value);
//static void debug_fillbyte(unsigned addr, uint8_t value, unsigned count);
//static void debug_fillhalf(unsigned addr, uint16_t value, unsigned count);
//static void debug_fillword(unsigned addr, unsigned value, unsigned count);
int strlong(char buff[], int pos, unsigned *value);
void console_mini(void);

uint8_t debugtcp_getchar(void);
void    debugtcp_puts(uint8_t *rcvbuf, int rcvlen);

#endif // __DEBUG_H
