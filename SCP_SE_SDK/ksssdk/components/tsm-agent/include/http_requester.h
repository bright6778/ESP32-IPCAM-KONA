/*
 * http_requester.h
 *
 *  Created on: Apr 13, 2018
 *      Author: Autonu
 */

#ifndef TSM_SDK_INCLUDE_HTTP_REQUESTER_H_
#define TSM_SDK_INCLUDE_HTTP_REQUESTER_H_

#include <stdlib.h>

#define HTTP_SUCCESS 200

// typedef enum {
//     HTTP_CURL_OK      = 0,
//     HTTP_CURL_FAILURE = -1,
// } HTTP_CURL_STATUS;

// typedef struct {
//     char *memory;   /* 동적 버퍼 */
//     size_t size;    /* 사용된 길이 */
// } MemoryStruct;
typedef enum _HTTP_CURL_STATUS
{
	HTTP_CURL_OK = 0,
	HTTP_CURL_INIT_FAILED,
	HTTP_CURL_FAILURE,
}HTTP_CURL_STATUS;

typedef struct _MemoryStruct
{
	char *memory;
	size_t size;
}MemoryStruct;


/**
 * @brief Info level logging macro.
 *
 * Macro to expose desired log message. Info messages do not include automatic function names and line numbers.
 */
#ifdef ENABLE_HTTP_INFO
#define HTTP_INFO(...)    \
	{\
	printf(__VA_ARGS__); \
	printf("\n"); \
	}
#else
#define HTTP_INFO(...)
#endif

/**
 * @brief Warn level logging macro.
 *
 * Macro to expose function, line number as well as desired log message.
 */
#ifdef ENABLE_HTTP_WARN
#define HTTP_WARN(...)   \
	{ \
	printf("WARN:  %s L#%d ", __func__, __LINE__);  \
	printf(__VA_ARGS__); \
	printf("\n"); \
	}
#else
#define HTTP_WARN(...)
#endif

/**
 * @brief Error level logging macro.
 *
 * Macro to expose function, line number as well as desired log message.
 */
#ifdef ENABLE_HTTP_ERROR
#define HTTP_ERROR(...)  \
	{ \
	printf("ERROR: %s L#%d ", __func__, __LINE__); \
	printf(__VA_ARGS__); \
	printf("\n"); \
	}
#else
#define HTTP_ERROR(...)
#endif

char* buildUrl(char* baseUrl, char* uri);
HTTP_CURL_STATUS requestHttp(char *postData, long postLength, char* url, MemoryStruct** returnData, int option);


#endif /* TSM_SDK_INCLUDE_HTTP_REQUESTER_H_ */
