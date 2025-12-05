
#ifdef ESP_PLATFORM
#include "driver/uart.h"
#endif
#include <stdarg.h>
#include "kona_kss_debug.h"

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
static const char *TAG = "DBG";

/////////////////////////////////////////////////////////////////////////////
//! @brief 디버그 메세지를 UART로 출력한다.
//! flag_debug가 0이면 출력하지 않는다.
//! @param[in] format : 출력할 메세지 포멧
/////////////////////////////////////////////////////////////////////////////

void kss_debug_printf(const char *format, ...)
{
	#ifdef KSS_DEBUG 
		va_list ap;
		char string[128];

		va_start(ap, format);
		vsprintf(string, format, ap);
        {
            // "\r\n" 제거
            int len = strlen(string);
            if (string[len - 1] == '\n') string[len - 1] = 0;
            if (string[len - 2] == '\r') string[len - 2] = 0;
        }
        //ESP_LOGI(TAG, "%s", string);
        LOGI(TAG, "%s", string);
		va_end(ap);
    #endif
}

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

void kss_debug_showframe(const char *title, const uint8_t *buf, int len)
{
#ifdef KSS_DEBUG
    if (!buf || len <= 0) {
        LOGI(TAG, "%s (len=%d): (empty)", title ? title : "FRAME", len);
        return;
    }

    const int bytes_per_line   = 32;  // 한 줄당 바이트 수
    char line[16 + bytes_per_line * 3 + 32];

    LOGI(TAG, "%s (len=%d)", title ? title : "FRAME", len);

    {
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos, "Addr  | ");
        for (int i = 0; i < bytes_per_line; ++i) {
            pos += snprintf(line + pos, sizeof(line) - pos, "%02X ", i);
        }
        line[pos] = '\0';
        LOGI(TAG, "%s", line);
    }

    for (int off = 0; off < len; off += bytes_per_line) {
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos, "%04X: | ", off);

        int chunk = len - off;
        if (chunk > bytes_per_line) chunk = bytes_per_line;

        for (int i = 0; i < chunk; ++i) {
            pos += snprintf(line + pos, sizeof(line) - pos, "%02X ", buf[off + i]);
        }

        for (int i = chunk; i < bytes_per_line; ++i) {
            pos += snprintf(line + pos, sizeof(line) - pos, "   ");
        }

        line[pos] = '\0';
        LOGI(TAG, "%s", line);
    }
#else
    (void)title; (void)buf; (void)len;
#endif
}

void kss_showframe(const char *title, const uint8_t *buf, int len)
{
    if (!buf || len <= 0) {
        LOGI(TAG, "%s (len=%d): (empty)", title ? title : "FRAME", len);
        return;
    }

    const int bytes_per_line   = 32;  // 한 줄당 바이트 수
    char line[16 + bytes_per_line * 3 + 32];

    LOGI(TAG, "%s (len=%d)", title ? title : "FRAME", len);

    {
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos, "Addr  | ");
        for (int i = 0; i < bytes_per_line; ++i) {
            pos += snprintf(line + pos, sizeof(line) - pos, "%02X ", i);
        }
        line[pos] = '\0';
        LOGI(TAG, "%s", line);
    }

    for (int off = 0; off < len; off += bytes_per_line) {
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos, "%04X: | ", off);

        int chunk = len - off;
        if (chunk > bytes_per_line) chunk = bytes_per_line;

        for (int i = 0; i < chunk; ++i) {
            pos += snprintf(line + pos, sizeof(line) - pos, "%02X ", buf[off + i]);
        }

        for (int i = chunk; i < bytes_per_line; ++i) {
            pos += snprintf(line + pos, sizeof(line) - pos, "   ");
        }

        line[pos] = '\0';
        LOGI(TAG, "%s", line);
    }
}
