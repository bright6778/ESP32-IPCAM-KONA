#pragma once

#ifndef __KSS_KOSE_MBEDTLS_H
#define __KSS_KOSE_MBEDTLS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "kona_kss_kose_config.h"
#include "kose_tlv.h"
#include "kss_kose_uart.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"

#ifdef DEBUG_PRINT
#include "esp_log.h"
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
        unsigned char *sig, size_t *sig_len,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng);

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

    int (*debug_func)(const void *, mbedtls_pk_debug_item *items);
} mbedtls_pk_info_t;

typedef struct
{
    /** @copydoc sss_asymmetric_t::session */
    //kss_kose_session_t *session;
    /** @copydoc sss_asymmetric_t::keyObject */
    //kss_kose_object_t *keyObject;
    /** @copydoc sss_asymmetric_t::algorithm */
    //kss_algorithm_t algorithm;
    /** @copydoc sss_asymmetric_t::mode */
    //kss_mode_t mode;

} kss_se05x_asymmetric_t;

//extern const mbedtls_pk_info_t kose_pk_info;
extern mbedtls_pk_info_t kose_mbedtls_eckeypair_pk_info;
extern mbedtls_pk_info_t kose_mbedtls_ecpubkey_pk_info;

void setup_se_default_pk_info();
static int kss_eckey_check_pair(const void *pub, const void *prv);
static int kss_eckeypair_can_do(mbedtls_pk_type_t type);
static int kss_ecpubkey_can_do(mbedtls_pk_type_t type);
static void kss_eckeypair_free_func(void *ctx);
static void kss_ecpubkey_free_func(void *ctx);

void cp_tls_register_with_mbedtls(mbedtls_ssl_config *config);

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

int kss_eckey_verify(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    const unsigned char *sig,
    size_t sig_len);

int kss_eckey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);

#ifdef __cplusplus
}
#endif
#endif /* MBEDTLS_H */