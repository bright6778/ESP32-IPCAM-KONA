#include "driver/uart.h"
#include "esp_err.h"
#include "esp_log.h"
#include "debug.h"


/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

static const char *TAG = "DBG";
static bool flag_debug = true;

/////////////////////////////////////////////////////////////////////////////
//! @brief 디버그 메세지를 UART로 출력한다.
//! flag_debug가 0이면 출력하지 않는다.
//! @param[in] format : 출력할 메세지 포멧
/////////////////////////////////////////////////////////////////////////////

void debug_printf(const char *format, ...)
{
	if (flag_debug) {
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
        ESP_LOGI(TAG, "%s", string);
		va_end(ap);
	}
}

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

void debug_showframe(char *title, uint8_t *buf, int len)
{
    {
        //printf("%s = [", title);
        //for (int i = 0; i < len; i++) {
        //    printf(i ? " %02x" : "%02x", buf[i]);
        //}
        //printf("](%d)\n", len);
    }

    if (flag_debug) {
        #define MAX_BUF_SIZE (128)
        char tmpbuf[MAX_BUF_SIZE + 8];
        int count = 0;
        count = sprintf(&tmpbuf[count], "%s = [", title);
        for (int i = 0; i < len; i++) {
            count += sprintf(&tmpbuf[count], i ? " %02x" : "%02x", buf[i]);
            if (count >= MAX_BUF_SIZE) {
                ESP_LOGI(TAG, "%s", tmpbuf);
                count = 0;
            }
        }
        if (count > 0) {
            ESP_LOGI(TAG, "%s](%d)", tmpbuf, len);
        }
        else {
            ESP_LOGI(TAG, "](%d)", len);
        }
    }
}