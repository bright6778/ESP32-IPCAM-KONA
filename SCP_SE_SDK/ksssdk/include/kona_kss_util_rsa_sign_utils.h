/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#ifndef KONA_KSS_UTIL_RSA_SIGN_H
#define KONA_KSS_UTIL_RSA_SIGN_H

#if KSS_HAVE_APPLET_KOSE_IOT && KSSFTR_RSA
#include "kona_kss_api.h"
#include "kona_kss_kose_types.h"
#include "sm_types.h"

uint8_t pkcs1_v15_encode(
    kss_kose_asymmetric_t *context, const uint8_t *hash, size_t hashlen, uint8_t *out, size_t *outLen, uint16_t key_size_bytes);

uint8_t pkcs1_v15_encode_no_hash(
    kss_kose_asymmetric_t *context, const uint8_t *hash, size_t hashlen, uint8_t *out, size_t *outLen, uint16_t key_size_bytes);

uint8_t kss_mgf_mask_func(uint8_t *dst, size_t dlen, uint8_t *src, size_t slen, kss_algorithm_t sha_algorithm);

uint8_t emsa_encode(kss_kose_asymmetric_t *context, const uint8_t *hash, size_t hashlen, uint8_t *out, size_t *outLen, uint16_t key_size_bytes);

uint8_t emsa_decode_and_compare(
    kss_kose_asymmetric_t *context, uint8_t *sig, size_t siglen, const uint8_t *hash, size_t hashlen);
#endif //KSS_HAVE_APPLET_KOSE_IOT && KSSFTR_RSA

#endif
