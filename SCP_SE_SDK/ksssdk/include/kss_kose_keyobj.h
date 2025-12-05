/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

/* ************************************************************************** */
/* Defines : kss_kose_keyobj                                                */
/* ************************************************************************** */
#define SYSTEM_FILE_START           0x0000
#define SYSTEM_FILE_END             0x00FF
#define ECC_KEYPAIR_PRIVATE_START   0x0100
#define ECC_KEYPAIR_PRIVATE_END     0X01FF
#define ECC_KEYPAIR_PUBLIC_START    0x0200
#define ECC_KEYPAIR_PUBLIC_END      0X02FF
#define AES_KEY_START               0x0400
#define AES_KEY_END                 0X04FF
#define ECC_ENT_KEYPAIR_START       0x0700
#define ECC_ENT_KEYPAIR_END         0X07FF
#define RSA_KEYPAIR_PRIVATE_START   0x0A00
#define RSA_KEYPAIR_PRIVATE_END     0X0AFF
#define RSA_KEYPAIR_PUBLIC_START    0x0900
#define RSA_KEYPAIR_PUBLIC_END      0X09FF

/**
 * @addtogroup kss_kose_keyobj
 * @{
 */
/** @copydoc kss_key_object_init
 *
 */
kss_status_t kss_kose_key_object_init(kss_kose_object_t *keyObject, kss_kose_key_store_t *keyStore);

kss_status_t kss_kose_key_object_allocate_handle(kss_kose_object_t *keyObject,
    uint32_t keyId,
    kss_key_part_t keyPart,
    kss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t acl,
    uint32_t options);

kss_status_t kss_kose_key_object_get_handle(kss_kose_object_t *keyObject, uint32_t objectId);

/** @copydoc kss_key_object_free
 *
 * On KOSE, this has no impact on physical Key Object.
 */
void kss_kose_key_object_free(kss_kose_object_t *keyObject);
