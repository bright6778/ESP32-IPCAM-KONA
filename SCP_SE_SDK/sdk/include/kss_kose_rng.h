/////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2025 Kona I Co., Ltd.
// 
// All rights are reserved.
// Proprietary and confidential.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Any use is subject to an appropriate license granted by Kona I Co., Ltd..
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//! @file    kose_rng.h
//! @brief   SE Session module
/////////////////////////////////////////////////////////////////////////////

#define __KOSE_RNG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "kona_kss_kose_types.h"
#include "kona_kss_kose_config.h"
#include "kose_tlv.h"
#include "kss_kose_uart.h"
#include "kss_kose_session.h"

#ifdef DEBUG_PRINT
#include "esp_log.h"
#include "debug.h"
#endif

#define AX_UNUSED_ARG(x) (void)(x)
#define SSS_RNG_MAX_CONTEXT_SIZE 32


/** Random number generator context */
typedef struct
{
    /** Pointer to the session */
    kss_session_t *session;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_RNG_MAX_CONTEXT_SIZE];
    } context;

} kss_rng_context_t;

kss_status_t kss_kose_rng_context_init(kss_rng_context_t *context, kss_kose_session_t *session);

/**
 * @brief Generate random number.
 *
 * @param   context random generator context.
 * @param   random_data buffer to hold random data.
 * @param   dataLen required random number length
 * @return  status
 */
kss_status_t kss_kose_rng_get_random(kss_rng_context_t *context, uint8_t *random_data, size_t dataLen);

/**
 * @brief free random genertor context.
 *
 * @param   context generator context.
 * @return  status
 */
kss_status_t kss_kose_rng_context_free(kss_rng_context_t *context);

#ifdef __cplusplus
}
#endif

/**
 *@}
 */ /* end of sss_rng */

/**
 * @addtogroup sss_crypto_tunnel
 * @{
 */

/** @brief Constructor for the tunnelling service context.
 *
 *      Earlier:
 *          sss_status_t sss_tunnel_context_init(
 *              sss_session_t *session, sss_tunnel_t *context);
 *
 *      Now: Parameters are swapped
 *          sss_status_t sss_tunnel_context_init(
 *              sss_tunnel_t *context, sss_session_t *session);
 *
 * @param[out] context Pointer to tunnel context. Tunnel context is updated on function return.
 * @param session Pointer to session this tunnelling service belongs to.
 */