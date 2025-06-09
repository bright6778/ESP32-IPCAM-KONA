/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

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
#include "debug.h"
#endif

#define AX_UNUSED_ARG(x) (void)(x)

kss_status_t kss_kose_rng_context_init(kss_kose_rng_context_t *context, kss_kose_session_t *session);

/**
 * @brief Generate random number.
 *
 * @param   context random generator context.
 * @param   random_data buffer to hold random data.
 * @param   dataLen required random number length
 * @return  status
 */
kss_status_t kss_kose_rng_get_random(kss_kose_rng_context_t *context, uint8_t *random_data, size_t dataLen);

/**
 * @brief free random genertor context.
 *
 * @param   context generator context.
 * @return  status
 */
kss_status_t kss_kose_rng_context_free(kss_kose_rng_context_t *context);

#ifdef __cplusplus
}
#endif

/**
 *@}
 */ /* end of sss_rng */
