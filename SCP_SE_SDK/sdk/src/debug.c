
#include "driver/uart.h"
#include "debug.h"

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
static const char *TAG = "DBG";
//static bool flag_debug = true;

/////////////////////////////////////////////////////////////////////////////
//! @brief 디버그 메세지를 UART로 출력한다.
//! flag_debug가 0이면 출력하지 않는다.
//! @param[in] format : 출력할 메세지 포멧
/////////////////////////////////////////////////////////////////////////////

void debug_printf(const char *format, ...)
{
	#ifdef DEBUG 
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

void debug_showframe(const char *title, const uint8_t *buf, int len)
{
    #ifdef DEBUG 
        #define MAX_BUF_SIZE (128)
        char tmpbuf[MAX_BUF_SIZE + 8];
        int count = 0;
        count = sprintf(&tmpbuf[count], "%s = [", title);
        for (int i = 0; i < len; i++) {
            count += sprintf(&tmpbuf[count], i ? " %02x" : "%02x", buf[i]);
            if (count >= MAX_BUF_SIZE) {
                //ESP_LOGI(TAG, "%s", tmpbuf);
                LOGI(TAG, "%s", tmpbuf);
                count = 0;
            }
        }
        if (count > 0) {
            //ESP_LOGI(TAG, "%s](%d)", tmpbuf, len);
            LOGI(TAG, "%s](%d)", tmpbuf, len);
        }
        else {
            //ESP_LOGI(TAG, "](%d)", len);
            LOGI(TAG, "](%d)", len);
        }
    #endif
}