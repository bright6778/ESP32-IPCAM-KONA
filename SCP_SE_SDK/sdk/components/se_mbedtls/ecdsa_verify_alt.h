/*
 * Copyright 2018-2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#include "kona_kss_api.h"

/* Internal macros meant to be called only from within the library. */
#define MBEDTLS_INTERNAL_VALIDATE_RET(cond, ret)  do { } while (0)
#define MBEDTLS_INTERNAL_VALIDATE(cond)           do { } while (0)

/*
 *  Set kss keystore for ecdsa verify
 */
void kss_mbedtls_set_kss_keystore(kss_key_store_t *ksskeystore);