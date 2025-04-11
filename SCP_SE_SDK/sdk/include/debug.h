#include <stdio.h>
#include <string.h>
#include <stdint.h>

/////////////////////////////////////////////////////////////////////////////
// Functions
/////////////////////////////////////////////////////////////////////////////

void debug_printf(const char *format, ...);
void debug_showframe(char *title, uint8_t *buf, int len);

#define ENSURE_OR_RETURN_ON_ERROR(CONDITION, RETURN_VALUE) \
if (!(CONDITION)) { \
    debug_printf("CONDITION:'" #CONDITION "' failed. At Line:%d Function:%s", __LINE__, __FUNCTION__); \
    return RETURN_VALUE; \
}
