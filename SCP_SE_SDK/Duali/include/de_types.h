/**
 * @file de_types.h
 * @author thuan@duali.com
 * @date 02/02/2023.
 * @brief This is the defined data type that is used in all of files.
 */

#ifndef DE_TYPES_H
#define DE_TYPES_H

#ifndef bool_t
typedef unsigned char bool_t;
#endif

#ifndef int8_t
typedef signed char  int8_t;
#endif

#ifndef char_t
typedef char char_t;
#endif

#ifndef uint8_t
typedef unsigned char uint8_t;
#endif

#ifndef int16_t
typedef short int16_t;
#endif

#ifndef uint16_t
typedef unsigned short uint16_t;
#endif

#ifndef int32_t
typedef int int32_t;
#endif

#ifndef uint32_t
typedef unsigned int uint32_t;
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef null
#define null NULL
#endif

#ifndef false
#define false 0
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef true
#define true 1
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef de_datetime_t
typedef struct de_datetime de_datetime_t;
struct de_datetime{
    uint16_t year;  // [from 1970]
    uint8_t mon;    // [1-12]
    uint8_t mday;   // day of month [1-31]
    uint8_t hour;   // [0-23]
    uint8_t min;    // [0-59]
    uint8_t sec;    // [0-59]
    uint8_t wday;   // [0-6] day of week, SUNDAY = 0

    int32_t tz;     // [-12->12] timezone England = 0
};
#endif

typedef void (*de_log_push_fn_t)(const char*);
typedef enum{
    DE_LOG_ERROR,
    DE_LOG_WARNING,
    DE_LOG_INFO,
    DE_LOG_DEBUG,
    DE_LOG_LEVEL_NUMBER
}DE_LOG_LEVEL;
#define DE_LOG_BUFFER_SIZE  512

#endif //DE_TYPES_H
