#include "mbedtls/x509_csr.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <stdio.h>
#include <string.h>
#include "kona_kss_api.h"
#include "kss_kose_mbedtls.h"
#ifdef DEBUG_PRINT
#include "kona_kss_debug.h"
#endif
static const char *TAG = "gen_csr.c";
int gen_csr(kss_session_t *session) {
    int ret;
    mbedtls_x509write_csr req;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "csr";
    unsigned char csr_buf[4096];

    // 1. 초기화
    mbedtls_x509write_csr_init(&req);
    mbedtls_pk_init(&key);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // 2. 랜덤 시드
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *) pers, strlen(pers))) != 0) {
        printf("mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
        return 1;
    }
    kss_object_t keyobject; // device private key object
	kss_key_store_t keystore;
    kss_status_t kss_status;

    kss_status = kss_key_store_context_init(&keystore, session);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_store_context_init failed res : %d", kss_status);      
    }

    LOGD(TAG, "keystore-sessionID : %d", keystore.session->subsystem);

	    kss_status = kss_key_object_init(&keyobject, &keystore);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_init failed res : %d", kss_status);
    }

	kss_status = kss_key_object_get_handle(&keyobject, 0x0100);
    if(kss_status != kStatus_KSS_Success){
        LOGE(TAG, "kss_key_object_get_handle failed res : %d", kss_status);
    }


    if(kss_mbedtls_sign(&key, &keyobject) != 0){    // <- 이 함수가 pk.pk_info, pk.pk_ctx 를 SE 기반으로 세팅
        LOGE(TAG, "kss_mbedtls_sign failed");
    }

    mbedtls_x509write_csr_set_subject_name(&req,
        "C=KR,ST=Some-State,O=Konai,OU=Konai,CN=Konai"
    );
    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&req, &key);
    LOGD(TAG, "mbedtls_x509write_csr_set_key + %p", req.private_key);


    LOGD(TAG, "mbedtls_pk_get_type: %d", mbedtls_pk_get_type(&key));
// 3. CSR 생성
     ret = mbedtls_x509write_csr_pem(&req, csr_buf, sizeof(csr_buf),  mbedtls_ctr_drbg_random, &ctr_drbg);

     if (ret == 0) {
          printf("%s", csr_buf); // CSR PEM 출력
    } else {
        printf("CSR PEM 생성 실패: -0x%04x\n", -ret);
    }

    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&key);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return 0;

 /*   // 4. CSR 준비 (Subject DN: C=KR, ST=Some-State, O=Konai, OU=Konai, CN=Konai)
    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&req, &keyobject);
    mbedtls_x509write_csr_set_subject_name(&req,
        "C=KR,ST=Some-State,O=Konai,OU=Konai,CN=Konai"
    );

    // 5. PEM 포맷 CSR 생성
    ret = mbedtls_x509write_csr_pem(&req, csr_buf, sizeof(csr_buf),
                                    mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret == 0) {
        printf("%s", csr_buf); // CSR PEM 출력
    } else {
        printf("CSR PEM 생성 실패: -0x%04x\n", -ret);
    }

    // 6. 자원 해제
    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&key);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return 0;*/
}

