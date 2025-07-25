#ifndef KSS_IDENTITY_H
#define KSS_IDENTITY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/// SE 내부 오브젝트 ID 매핑 구조체
typedef struct {
    uint16_t device_id;           // 0x0001
    uint16_t ecc_priv_key_id;     // 0x0101
    uint16_t ecc_pub_key_id;      // 0x0201
    uint16_t scp03_keyset_id;     // 0x0300
    uint16_t device_cert_id;      // 0x0701
} se_object_id_t;

/// TSM Agent가 관리하는 장치 식별 정보 구조체
typedef struct {
    char device_id[64];           // TSM에서 부여한 고유 ID
    char seid[64];                // SE에서 읽어온 SEID

    uint8_t public_key[256];      // SE에서 가져온 공개 키
    size_t public_key_len;

    char cert_pem[2048];          // TSM에서 발급받은 인증서 (PEM)
    bool cert_installed;

    bool keypair_generated;       // 키쌍 생성 여부
    bool csr_sent;                // CSR 전송 여부

    se_object_id_t object_ids;    // SE Object ID 매핑
} tsm_agent_identity_t;

#endif // KSS_IDENTITY_H
