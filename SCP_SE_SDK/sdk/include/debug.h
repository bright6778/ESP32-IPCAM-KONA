#pragma once

#define DEBUG

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/////////////////////////////////////////////////////////////////////////////
// Defines
/////////////////////////////////////////////////////////////////////////////
// ANSI 색상 코드
#define ANSI_COLOR_RED     "\x1B[31m"
#define ANSI_COLOR_GREEN   "\x1B[32m"
#define ANSI_COLOR_YELLOW  "\x1B[33m"
#define ANSI_COLOR_RESET   "\x1B[0m"

#define MBEDTLS_DEBUG_C
/////////////////////////////////////////////////////////////////////////////
// Functions
/////////////////////////////////////////////////////////////////////////////
#define LOGI(tag, fmt, ...) printf(ANSI_COLOR_GREEN "[INF] %s: " fmt "\n", tag, ##__VA_ARGS__);
#define LOGE(tag, fmt, ...) printf(ANSI_COLOR_RED "[ERR] %s: " fmt "\n", tag, ##__VA_ARGS__);

#ifdef DEBUG
#define LOGD(tag, fmt, ...) printf(ANSI_COLOR_YELLOW "[DBG] %s: " fmt "\n", tag, ##__VA_ARGS__);
#else
//#define LOGI(tag, fmt, ...) do {} while (0);
//#define LOGE(tag, fmt, ...) do {} while (0);
#define LOGD(tag, fmt, ...) do {} while (0);
#endif

void debug_printf(const char *format, ...);
void debug_showframe(char *title, uint8_t *buf, int len);
/*
#define ENSURE_OR_RETURN_ON_ERROR(CONDITION, RETURN_VALUE) \
if (!(CONDITION)) { \
    debug_printf(ANSI_COLOR_YELLOW "CONDITION:'" #CONDITION "' failed. At Line:%d Function:%s", __LINE__, __FUNCTION__); \
    return RETURN_VALUE; \
}
*/