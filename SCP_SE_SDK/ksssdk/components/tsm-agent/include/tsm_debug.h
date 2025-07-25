/*
 * tsm_debug.h
 *
 *  Created on: Jun 14, 2018
 *      Author: GM Al Mamun
 */

#ifndef TSM_SDK_INCLUDE_TSM_DEBUG_H_
#define TSM_SDK_INCLUDE_TSM_DEBUG_H_

#include <stddef.h>


//#ifdef ENABLE_TSM_SDK_DEBUG

#define TSM_SDK_DEBUG_MSG( level, ... )                    \
    tsm_sdk_debug_print_msg( level, __FILE__, __LINE__, __VA_ARGS__ )

#define TSM_SDK_DEBUG_RET( level, text, ret )                \
    tsm_sdk_debug_print_ret( level, __FILE__, __LINE__, text, ret )

#define TSM_SDK_DEBUG_BUF( level, text, buf, len )           \
    tsm_sdk_debug_print_buf( level, __FILE__, __LINE__, text, buf, len )

int tsm_sdk_debug_init();

void tsm_sdk_debug_print_msg( int level,
                              const char *file, int line,
                              const char *format, ... );

void tsm_sdk_debug_print_ret(int level,
                      const char *file, int line,
                      const char *text, int ret );

void tsm_sdk_debug_print_buf( int level,
                      const char *file, int line, const char *text,
                      const unsigned char *buf, size_t len );

//#endif

#endif /* TSM_SDK_INCLUDE_TSM_DEBUG_H_ */
