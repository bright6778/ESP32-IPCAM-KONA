/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#ifndef __KSS_KOSE_SESSION_H
#define __KSS_KOSE_SESSION_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef DEBUG_PRINT
#include "debug.h"
#endif

// Function Declaration
kss_status_t kss_kose_session_create(kss_kose_session_t *session);
    
kss_status_t kss_kose_session_open(kss_kose_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData);

void kss_kose_session_close(kss_kose_session_t *session);

#ifdef __cplusplus
}
#endif
#endif