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
