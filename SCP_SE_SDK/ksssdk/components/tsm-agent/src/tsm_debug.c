/*
 * tsm_debug.c
 *
 *  Created on: Jun 14, 2018
 *      Author: GM Al Mamun
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define TSM_DEBUG_BUF_SIZE      512
#define TSM_DEBUG_LEVEL 	4

#if TSM_DEBUG_LEVEL > 0

#define tsm_sdk_snprintf   snprintf


FILE *tsm_sdk_debug_fp;

int tsm_sdk_debug_init()
{
	tsm_sdk_debug_fp = fopen("tsm_sdk.log", "w");

	if(tsm_sdk_debug_fp == NULL)
	{
		printf("\nCould not open tsm_sdk.log file to write tsm log\n");
		return -1;
	}

	return 0;
}

/**
 * Debug callback for mbed TLS
 * Just prints on the USB serial port
 */
static void tsm_sdk_debug(void *ctx, int level, const char *file, int line,
					 const char *str)
{
	const char *p, *basename;
//	(void) ctx;

	/* Extract basename from file */
	for(p = basename = file; *p != '\0'; p++) {
		if(*p == '/' || *p == '\\') {
			basename = p + 1;
		}
	}

    fprintf(tsm_sdk_debug_fp, "%s:%04d: |%d| %s", basename, line, level, str);
    fflush(tsm_sdk_debug_fp);
    printf("%s:%04d: |%d| %s", basename, line, level, str);
}
#endif

static inline void debug_send_line( int level,
                                    const char *file, int line,
                                    const char *str )
{
    /*
     * If in a threaded environment, we need a thread identifier.
     * Since there is no portable way to get one, use the address of the ssl
     * context instead, as it shouldn't be shared between threads.
     */
#if defined(MBEDTLS_THREADING_C)
    char idstr[20 + DEBUG_BUF_SIZE]; /* 0x + 16 nibbles + ': ' */
    mbedtls_snprintf( idstr, sizeof( idstr ), "%p: %s", (void*)ssl, str );
    ssl->conf->f_dbg( ssl->conf->p_dbg, level, file, line, idstr );
#else
//    ssl->conf->f_dbg( ssl->conf->p_dbg, level, file, line, str );
    tsm_sdk_debug(NULL, level, file, line, str);
#endif
}

void tsm_sdk_debug_print_msg( int level,
                              const char *file, int line,
                              const char *format, ... )
{
    va_list argp;
    char str[TSM_DEBUG_BUF_SIZE];
    int ret;

//    if( NULL == ssl || NULL == ssl->conf || NULL == ssl->conf->f_dbg || level > debug_threshold )
//        return;

    va_start( argp, format );
#if defined(_WIN32)
#if defined(_TRUNCATE)
    ret = _vsnprintf_s( str, DEBUG_BUF_SIZE, _TRUNCATE, format, argp );
#else
    ret = _vsnprintf( str, DEBUG_BUF_SIZE, format, argp );
    if( ret < 0 || (size_t) ret == DEBUG_BUF_SIZE )
    {
        str[DEBUG_BUF_SIZE-1] = '\0';
        ret = -1;
    }
#endif
#else
    ret = vsnprintf( str, TSM_DEBUG_BUF_SIZE, format, argp );
#endif
    va_end( argp );

    if( ret >= 0 && ret < TSM_DEBUG_BUF_SIZE - 1 )
    {
        str[ret]     = '\n';
        str[ret + 1] = '\0';
    }

    debug_send_line( level, file, line, str );
}

void tsm_sdk_debug_print_ret(int level,
                      const char *file, int line,
                      const char *text, int ret )
{
    char str[TSM_DEBUG_BUF_SIZE];

//    if( ssl->conf == NULL || ssl->conf->f_dbg == NULL || level > debug_threshold )
//        return;

    /*
     * With non-blocking I/O and examples that just retry immediately,
     * the logs would be quickly flooded with WANT_READ, so ignore that.
     * Don't ignore WANT_WRITE however, since is is usually rare.
     */
//    if( ret == MBEDTLS_ERR_SSL_WANT_READ )
//        return;

    tsm_sdk_snprintf( str, sizeof( str ), "%s() returned %d (-0x%04x)\n",
              text, ret, -ret );

    debug_send_line( level, file, line, str );
}

void tsm_sdk_debug_print_buf( int level,
                      const char *file, int line, const char *text,
                      const unsigned char *buf, size_t len )
{
    char str[TSM_DEBUG_BUF_SIZE];
    char txt[17];
    size_t i, idx = 0;

//    if( ssl->conf == NULL || ssl->conf->f_dbg == NULL || level > debug_threshold )
//        return;

    tsm_sdk_snprintf( str + idx, sizeof( str ) - idx, "dumping '%s' (%u bytes)\n",
              text, (unsigned int) len );

    debug_send_line( level, file, line, str );

    idx = 0;
    memset( txt, 0, sizeof( txt ) );
    for( i = 0; i < len; i++ )
    {
        if( i >= 4096 )
            break;

        if( i % 16 == 0 )
        {
            if( i > 0 )
            {
            	tsm_sdk_snprintf( str + idx, sizeof( str ) - idx, "  %s\n", txt );
                debug_send_line( level, file, line, str );

                idx = 0;
                memset( txt, 0, sizeof( txt ) );
            }

            idx += tsm_sdk_snprintf( str + idx, sizeof( str ) - idx, "%04x: ",
                             (unsigned int) i );

        }

        idx += tsm_sdk_snprintf( str + idx, sizeof( str ) - idx, " %02x",
                         (unsigned int) buf[i] );
        txt[i % 16] = ( buf[i] > 31 && buf[i] < 127 ) ? buf[i] : '.' ;
    }

    if( len > 0 )
    {
        for( /* i = i */; i % 16 != 0; i++ )
            idx += tsm_sdk_snprintf( str + idx, sizeof( str ) - idx, "   " );

        tsm_sdk_snprintf( str + idx, sizeof( str ) - idx, "  %s\n", txt );
        debug_send_line( level, file, line, str );
    }
}
