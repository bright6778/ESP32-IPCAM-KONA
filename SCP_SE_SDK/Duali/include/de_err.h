/**
 * @file de_err.h
 * @author thuan@duali.com
 * @date 02/02/2023.
 * @brief This is Error Codes that is defined by Duali Electronic. All of APIs will be returned error code defined here.
 */

#ifndef DE_ERR_H
#define DE_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

#define DE_ERR_NONE                     0
#define DE_ERR_NO_INIT                  -1
#define DE_ERR_WRONG_PARAM              -2
#define DE_ERR_COMMON                   -3
#define DE_ERR_UNKNOWN                  -4
#define DE_ERR_TIMEOUT                  -5
#define DE_ERR_NOT_SUPPORT              -6
#define DE_ERR_BUSY                     -7
#define DE_ERR_ALLOCATE_MEMORY          -8
#define DE_ERR_OPEN_FS                  -9

#ifdef __cplusplus
}
#endif

#endif //DE_ERR_H
