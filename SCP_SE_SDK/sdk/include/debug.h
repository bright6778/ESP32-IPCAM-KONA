#pragma once

#define DEBUG

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/////////////////////////////////////////////////////////////////////////////
// Functions
/////////////////////////////////////////////////////////////////////////////
#ifdef DEBUG
#define LOGI(tag, fmt, ...) printf("[INFO] %s: " fmt "\n", tag, ##__VA_ARGS__);
#define LOGE(tag, fmt, ...) printf("[ERR ] %s: " fmt "\n", tag, ##__VA_ARGS__);
#else
#define LOGI(tag, fmt, ...) do {} while (0);
#define LOGE(tag, fmt, ...) do {} while (0);
#endif

void debug_printf(const char *format, ...);
void debug_showframe(char *title, uint8_t *buf, int len);

#define ENSURE_OR_RETURN_ON_ERROR(CONDITION, RETURN_VALUE) \
if (!(CONDITION)) { \
    debug_printf("CONDITION:'" #CONDITION "' failed. At Line:%d Function:%s", __LINE__, __FUNCTION__); \
    return RETURN_VALUE; \
}
