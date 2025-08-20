#include <stdio.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"

#include "kona_kss_api.h"
#include "kss_kose_mbedtls.h"   // kss_mbedtls_sign()
#ifdef DEBUG_PRINT
#include "kona_kss_debug.h"
#endif

#ifndef TAG
#define TAG "gen_csr"
#endif

// 필요 시 조정
#define DEV_PRIV_OBJ_ID   0x0100  // SE 내부 개인키 핸들
#define DEV_PUB_OBJ_ID    0x0200  // 공개키 오브젝트(보통 uncompressed 0x04|X|Y)
#define CSR_SUBJECT_DN    "C=KR,ST=Some-State,O=Konai,OU=Konai,CN=Konai"


static void print_err(const char *where, int ret)
{
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    printf("ERR %s: %s (ret=-0x%04X)\n", where, buf, -ret);
}

// uncompressed(0x04|X|Y) → X,Y 포인터/길이 추출
static int split_uncompressed_xy(const uint8_t *in, size_t in_len,
                                 const uint8_t **px, const uint8_t **py, size_t *q_len)
{
    if (in_len < 1 + 2*1) return -1;
    if (in[0] != 0x04) return -2; // 반드시 uncompressed로 온다고 가정
    size_t half = (in_len - 1) / 2;
    if (1 + 2*half != in_len) return -3;
    *px = in + 1;
    *py = in + 1 + half;
    *q_len = half;
    return 0;
}

int gen_csr(kss_session_t *session)
{
    int ret = -1;
    char errbuf[128];

    // ── 0) 인자/컨텍스트
    if (!session) { printf("ERR: session is NULL\n"); return -1; }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509write_csr req;
    mbedtls_pk_context pk;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509write_csr_init(&req);
    mbedtls_pk_init(&pk);

    const char *pers = "csr";


    // ── 1) RNG
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) { print_err("ctr_drbg_seed", ret); goto cleanup; }

    // ── 2) KSS Keystore + Key handles
    kss_key_store_t keystore;
    kss_status_t krc;

    krc = kss_key_store_context_init(&keystore, session);
    if (krc != kStatus_KSS_Success) {
        printf("ERR: kss_key_store_context_init: 0x%08X\n", (unsigned)krc);
        goto cleanup;
    }

    kss_object_t dev_priv, dev_pub;
    memset(&dev_priv, 0, sizeof(dev_priv));
    memset(&dev_pub, 0, sizeof(dev_pub));

    krc = kss_key_object_init(&dev_priv, &keystore);
    if (krc != kStatus_KSS_Success) { printf("ERR: key_object_init(priv): 0x%08X\n", (unsigned)krc); goto cleanup; }
    krc = kss_key_object_get_handle(&dev_priv, DEV_PRIV_OBJ_ID);
    if (krc != kStatus_KSS_Success) { printf("ERR: key_object_get_handle(priv): 0x%08X\n", (unsigned)krc); goto cleanup; }

    krc = kss_key_object_init(&dev_pub, &keystore);
    if (krc != kStatus_KSS_Success) { printf("ERR: key_object_init(pub): 0x%08X\n", (unsigned)krc); goto cleanup; }
    krc = kss_key_object_get_handle(&dev_pub, DEV_PUB_OBJ_ID);
    if (krc != kStatus_KSS_Success) { printf("ERR: key_object_get_handle(pub): 0x%08X\n", (unsigned)krc); goto cleanup; }

    // ── 3) 공개키 읽기 (보통 uncompressed 65바이트: 0x04|32|32 for P-256)
    uint8_t pub_buf[1 + 2*MBEDTLS_ECP_MAX_BYTES];
    size_t pub_len = sizeof(pub_buf);
    memset(pub_buf, 0, sizeof(pub_buf));


    krc = kss_key_store_get_data(&keystore, &dev_pub, pub_buf, &pub_len);
    if (krc != kStatus_KSS_Success) {
        printf("ERR: kss_key_store_get_data(pub): 0x%08X\n", (unsigned)krc);
        goto cleanup;
    }

    const uint8_t *qx = NULL, *qy = NULL;
    size_t q_len = 0;
    if ((ret = split_uncompressed_xy(pub_buf, pub_len, &qx, &qy, &q_len)) != 0) {
        printf("ERR: public key format (expect uncompressed 0x04|X|Y), ret=%d\n", ret);
        goto cleanup;
    }

    // ── 4) pk 컨텍스트를 SE-서명으로 래핑 (개인키는 SE에서 서명)
    //      kss_mbedtls_sign()은 pk.pk_info를 커스텀으로 설정하고 pk.pk_ctx를 할당(ecdsa)해줍니다.
    if (kss_mbedtls_sign(&pk, &dev_priv) != 0) {
        printf("ERR: kss_mbedtls_sign failed\n");
        goto cleanup;
        
    }

    // (검증) 공개키 DER이 써지는지 먼저 확인 → CSR 성공 여부의 바로미터
    
        unsigned char tmp[256];
        ret = mbedtls_pk_write_pubkey_der(&pk, pub_buf, pub_len);
        if (ret < 0) { print_err("pk_write_pubkey_der", ret); goto cleanup; }
    

    // ── 6) CSR 작성
    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);

    ret = mbedtls_x509write_csr_set_subject_name(&req, CSR_SUBJECT_DN);
    if (ret != 0) { print_err("set_subject_name", ret); goto cleanup; }

    mbedtls_x509write_csr_set_key(&req, &pk);

    unsigned char csr_pem[2048];
    memset(csr_pem, 0, sizeof(csr_pem));

    ret = mbedtls_x509write_csr_pem(&req, csr_pem, sizeof(csr_pem),
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) { print_err("x509write_csr_pem", ret); goto cleanup; }

    // ── 7) 출력 (필요 시 파일 저장으로 변경)
    printf("%s", (char*)csr_pem);

    ret = 0;

cleanup:
    if (ret != 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        printf("gen_csr failed: %s (ret=-0x%04X)\n", errbuf, -ret);
    }
    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

