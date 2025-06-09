/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#ifndef __KSS_KOSE_MBEDTLS_H
#define __KSS_KOSE_MBEDTLS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"

#include "kona_kss_mbedtls_types.h"

#ifdef DEBUG_PRINT
#include "debug.h"
#endif

typedef struct mbedtls_pk_info_t{
    /** Public key type */
    mbedtls_pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_bitlen)(const void *);

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
    int (*can_do)(mbedtls_pk_type_t type);

    /** Verify signature */
    int (*verify_func)(void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len);
    
    /** Make signature */
    int (*sign_func)(void *ctx, mbedtls_md_type_t md_alg,
        const unsigned char *hash, size_t hash_len,
        unsigned char *sig, size_t sig_size, size_t *sig_len,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng);
        
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /** Verify signature (restartable) */
    int (*verify_rs_func)(void *ctx, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len,
                          void *rs_ctx);

    /** Make signature (restartable) */
    int (*sign_rs_func)(void *ctx, mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng, void *rs_ctx);
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    /** Decrypt message */
    int (*decrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng);

    /** Encrypt message */
    int (*encrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
            unsigned char *output, size_t *olen, size_t osize,
            int (*f_rng)(void *, unsigned char *, size_t),
            void *p_rng);

    /** Check public-private key pair */
    int (*check_pair_func)(const void *pub, const void *prv);

    void *(*ctx_alloc_func)(void);
    void (*ctx_free_func)(void *);

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /** Allocate the restart context */
    void *(*rs_alloc_func)(void);

    /** Free the restart context */
    void (*rs_free_func)(void *rs_ctx);
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    int (*debug_func)(const void *, mbedtls_pk_debug_item *items);
} mbedtls_pk_info_t;

//extern const mbedtls_pk_info_t kose_pk_info;
extern const mbedtls_pk_info_t kose_mbedtls_eckeypair_pk_info;
extern const mbedtls_pk_info_t kose_mbedtls_ecpubkey_pk_info;
/*
static int kss_eckey_check_pair(const void *pub, const void *prv);
static int kss_eckeypair_can_do(mbedtls_pk_type_t type);
static int kss_ecpubkey_can_do(mbedtls_pk_type_t type);
static void kss_eckeypair_free_func(void *ctx);
static void kss_ecpubkey_free_func(void *ctx);
static void *kss_eckey_alloc(void);
*/
/**
 * @brief      Associate a keypair provisioned in the secure element for
 *             subsequent operations.
 *
 * @param[in]  key_index  Index in which the keypair is provisoned in the SE
 * @param[out] pkey       Pointer to the mbedtls_pk_context which will be
 *                        associated with data corresponding to the key_index
 *
 * @return     0 if successful, or 1 if unsuccessful
 */
//int mbedtls_associate_keypair(SST_Index_t key_index, mbedtls_pk_context * pkey);

/**
 * @brief      Associate a pubkey provisioned in the secure element for
 *             subsequent operations.
 *
 * @param[in]  key_index  Index in which the pub key is provisioned in the SE
 * @param[out] pkey       Pointer to the mbedtls_pk_context which will be
 *                        associated with data corresponding to the key index
 *
 * @return     0 if successful, or 1 if unsuccessful
 */
//int mbedtls_associate_pubkey(SST_Index_t key_index, mbedtls_pk_context * pkey);

/**
 * @brief         Update ECDSA HandShake key with given inded.
 *
 * @param[in]     key_index  Index in which the pub key is provisioned in the SE
 * @param[in,out] handshake  Pointer to the mbedtls_ssl_handshake_params which
 *                           will be associated with data corresponding to the
 *                           key index
 *
 * @return        0 if successful, or 1 if unsuccessful
 */

//int mbedtls_associate_ecdhctx(SST_Index_t key_index, mbedtls_ssl_handshake_params * handshake);
/*
static int kss_eckey_verify(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    const unsigned char *sig,
    size_t sig_len);

static int kss_eckey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t sig_size,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);
*/
int kss_mbedtls_associate_pubkey(mbedtls_pk_context *pkey, kss_object_t *pkeyObject);
int kss_mbedtls_associate_keypair(mbedtls_pk_context *pkey, kss_object_t *pkeyObject);
int kss_mbedtls_se_random(void *p_rng, unsigned char *output, size_t output_len);
int kss_mbedtls_parse_keyfile(const uint8_t *pem, size_t pem_len, uint8_t *d_buf, size_t *d_bufLen);
int kss_mbedtls_parse_crt_getpublickey(const uint8_t *cert, size_t cert_len, uint8_t *pub_buf, size_t *pub_len);

#ifdef __cplusplus
}
#endif
#endif /* MBEDTLS_H */