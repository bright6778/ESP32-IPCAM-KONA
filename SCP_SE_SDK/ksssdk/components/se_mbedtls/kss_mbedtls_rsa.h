#pragma once
#include "mbedtls/pk.h"

typedef int (*kss_pk_verify_f)( void *ctx, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig,  size_t sig_len );
typedef int (*kss_pk_sign_f)  ( void *ctx, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng );
typedef int (*kss_pk_decrypt_f)( void *ctx, const unsigned char *input, size_t ilen,
                                 unsigned char *output, size_t *olen, size_t osize,
                                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
typedef int (*kss_pk_encrypt_f)( void *ctx, const unsigned char *input, size_t ilen,
                                 unsigned char *output, size_t *olen, size_t osize,
                                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
typedef int (*kss_pk_check_pair_f)( const void *pub, const void *prv );
typedef void *(*kss_pk_alloc_f)( void );
typedef void  (*kss_pk_free_f) ( void *ctx );
typedef void  (*kss_pk_clone_f)( void *dst, const void *src );
typedef void  (*kss_pk_debug_f)( const void *ctx, mbedtls_pk_debug_item *items );


static size_t kss_rsakey_get_bitlen(const void *ctx);
static int kss_rsakey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);
static int kss_rsakey_verify(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    const unsigned char *sig,
    size_t sig_len);
static int kss_rsakey_check_pair(const void *pub, const void *prv);
static int kss_rsakeypair_can_do(mbedtls_pk_type_t type);
static int kss_rsapubkey_can_do(mbedtls_pk_type_t type);
static void kss_rsakeypair_free_func(void *ctx);
static void kss_rsapubkey_free_func(void *ctx);

//extern const mbedtls_pk_info_t kose_mbedtls_rsakeypair_info;
//extern const mbedtls_pk_info_t kose_mbedtls_rsapubkey_info;