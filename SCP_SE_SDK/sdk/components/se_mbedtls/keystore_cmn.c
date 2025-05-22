/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* Common Key store implementation between keystore_a7x and keystore_pc */

static const char *TAG = "keystore_cmn.c";

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "kona_kss_ftr_default.h"
#include "kona_kss_keyid_map.h"
#include <inttypes.h>
//#include <nxLog_App.h>
#include <stdio.h>
#include <string.h>
#include "sm_types.h"

#ifdef DEBUG_PRINT
#include "debug.h"
#endif

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define KEYSTORE_MAGIC (0xA71C401L)
#define KEYSTORE_VERSION (0x0004)

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */
kss_status_t keystore_shadow_From2_To_3(keyStoreTable_t *keystore_shadow);
kss_status_t keystore_shadow_From3_To_4(keyStoreTable_t *keystore_shadow);

void ks_common_init_fat(keyStoreTable_t *keystore_shadow, keyIdAndTypeIndexLookup_t *lookup_entires, size_t max_entries)
{
    memset(keystore_shadow, 0, sizeof(*keystore_shadow));
    keystore_shadow->magic      = KEYSTORE_MAGIC;
    keystore_shadow->version    = KEYSTORE_VERSION;
    keystore_shadow->maxEntries = 0;
    keystore_shadow->entries    = lookup_entires;

    if (max_entries > UINT16_MAX) {
        LOGE(TAG, "max_entries should be 2 bytes");
        return;
    }
    keystore_shadow->maxEntries = (uint16_t)max_entries;
    memset(keystore_shadow->entries, 0, sizeof(*lookup_entires) * max_entries);
}

kss_status_t ks_common_update_fat(keyStoreTable_t *keystore_shadow,
    uint32_t extId,
    kss_key_part_t key_part,
    kss_cipher_type_t cipherType,
    uint8_t intIndex,
    uint32_t accessPermission,
    uint16_t keyLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
    uint32_t i;
    bool found_entry         = false;
    uint8_t slots_req        = 1;
    uint8_t entries_written  = 0;
    uint16_t keyLen_roundoff = 0;

    AX_UNUSED_ARG(accessPermission);

    retval = isValidKeyStoreShadow(keystore_shadow);
    if (retval != kStatus_KSS_Success) {
        goto cleanup;
    }
    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry->extKeyId == extId) {
            LOGE(TAG, "ENTRY already exists %ld", extId);
            retval      = kStatus_KSS_Fail;
            found_entry = true;
            break;
        }
    }

    if (key_part == kKSS_KeyPart_Default && (cipherType == kKSS_CipherType_AES || cipherType == kKSS_CipherType_HMAC)) {
        if ((keyLen > (UINT16_MAX - 16)) || (keyLen == 0)) {
            retval = kStatus_KSS_Fail;
            goto cleanup;
        }
        keyLen_roundoff = ((keyLen / 16u) * 16u) + ((keyLen % 16u) == 0u ? 0u : 16u);
        if ((keyLen_roundoff / 16) > UINT8_MAX) {
            retval = kStatus_KSS_Fail;
            goto cleanup;
        }
        slots_req = (keyLen_roundoff / 16u);
    }

    if (!found_entry) {
        retval = kStatus_KSS_Fail;
        for (i = 0; i < keystore_shadow->maxEntries; i++) {
            keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
            if (keyEntry->extKeyId == 0) {
                keyEntry->extKeyId    = extId;
                keyEntry->keyIntIndex = intIndex;
                keyEntry->keyPart     = key_part | ((slots_req - 1u) << 4);
                keyEntry->cipherType  = cipherType;
                //keyEntry->accessPermission = accessPermission;

                entries_written++;
                if (entries_written == slots_req) {
                    retval = kStatus_KSS_Success;
                    break;
                }
            }
        }
    }
cleanup:
    return retval;
}

kss_status_t ks_common_remove_fat(keyStoreTable_t *keystore_shadow, uint32_t extId)
{
    kss_status_t retval = kStatus_KSS_Fail;
    uint32_t i;
    bool found_entry = false;
    retval           = isValidKeyStoreShadow(keystore_shadow);
    if (retval != kStatus_KSS_Success) {
        goto cleanup;
    }

    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry->extKeyId == extId) {
            retval = kStatus_KSS_Success;
            memset(keyEntry, 0, sizeof(keyIdAndTypeIndexLookup_t));
            found_entry = true;
        }
    }
    if (!found_entry) {
        retval = kStatus_KSS_Fail;
    }
cleanup:
    return retval;
}

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

kss_status_t keystore_shadow_From2_To_3(keyStoreTable_t *keystore_shadow)
{
    int i = 0;
    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry != NULL) {
            uint16_t org_keyIntIndex = (keyEntry->cipherType) | ((keyEntry->keyIntIndex) << 8);

            switch (keyEntry->keyPart) {
            case 0:
                continue;
            case 1:
                keyEntry->keyPart    = kKSS_KeyPart_Default;
                keyEntry->cipherType = kKSS_CipherType_Certificate;
                break;
            case 2:
                keyEntry->keyPart    = kKSS_KeyPart_Default;
                keyEntry->cipherType = kKSS_CipherType_AES;
                break;
            case 3:
                keyEntry->keyPart    = kKSS_KeyPart_Default;
                keyEntry->cipherType = kKSS_CipherType_DES;
                break;
            case 4:
                keyEntry->keyPart    = kKSS_KeyPart_Default;
                keyEntry->cipherType = kKSS_CipherType_CMAC;
                break;
#if KSSFTR_RSA
            case 5:
                keyEntry->keyPart    = kKSS_KeyPart_Public;
                keyEntry->cipherType = kKSS_CipherType_RSA_CRT;
                break;
#endif
            case 6:
                keyEntry->keyPart    = kKSS_KeyPart_Public;
                keyEntry->cipherType = kKSS_CipherType_EC_NIST_P;
                break;
            case 7:
                keyEntry->keyPart    = kKSS_KeyPart_Public;
                keyEntry->cipherType = kKSS_CipherType_EC_MONTGOMERY;
                break;
            case 8:
                keyEntry->keyPart    = kKSS_KeyPart_Public;
                keyEntry->cipherType = kKSS_CipherType_EC_TWISTED_ED;
                break;
#if KSSFTR_RSA
            case 9:
                keyEntry->keyPart    = kKSS_KeyPart_Private;
                keyEntry->cipherType = kKSS_CipherType_RSA_CRT;
                break;
#endif
            case 10:
                keyEntry->keyPart    = kKSS_KeyPart_Private;
                keyEntry->cipherType = kKSS_CipherType_EC_NIST_P;
                break;
            case 11:
                keyEntry->keyPart    = kKSS_KeyPart_Private;
                keyEntry->cipherType = kKSS_CipherType_EC_MONTGOMERY;
                break;
            case 12:
                keyEntry->keyPart    = kKSS_KeyPart_Private;
                keyEntry->cipherType = kKSS_CipherType_EC_TWISTED_ED;
                break;
#if KSSFTR_RSA
            case 13:
                keyEntry->keyPart    = kKSS_KeyPart_Pair;
                keyEntry->cipherType = kKSS_CipherType_RSA_CRT;
                break;
#endif
            case 14:
                keyEntry->keyPart    = kKSS_KeyPart_Pair;
                keyEntry->cipherType = kKSS_CipherType_EC_NIST_P;
                break;
            case 15:
                keyEntry->keyPart    = kKSS_KeyPart_Pair;
                keyEntry->cipherType = kKSS_CipherType_EC_MONTGOMERY;
                break;
            case 16:
                keyEntry->keyPart    = kKSS_KeyPart_Pair;
                keyEntry->cipherType = kKSS_CipherType_EC_TWISTED_ED;
                break;
            case 17:
                keyEntry->keyPart    = kKSS_KeyPart_Default;
                keyEntry->cipherType = kKSS_CipherType_UserID;
                break;
            default:
                LOGE(TAG, "Error in keystore_shadow_From2_To_3");
                return kStatus_KSS_Fail;
            }

            if (org_keyIntIndex > UINT8_MAX) {
                return kStatus_KSS_Fail;
            }
            keyEntry->keyIntIndex = (uint8_t)org_keyIntIndex;
        }
    }

    return kStatus_KSS_Success;
}

kss_status_t keystore_shadow_From3_To_4(keyStoreTable_t *keystore_shadow)
{
    int i = 0;
    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry != NULL) {
            switch (keyEntry->keyPart) {
            case kKSS_KeyPart_NONE:
                break;
            case kKSS_KeyPart_Default:
                if (keyEntry->cipherType == kKSS_CipherType_Certificate) {
                    keyEntry->cipherType = kKSS_CipherType_Binary;
                }
                break;
            default:
                LOGE(TAG, "Error in keystore_shadow_From3_To_4");
                return kStatus_KSS_Fail;
            }
        }
    }

    return kStatus_KSS_Success;
}

kss_status_t isValidKeyStoreShadow(keyStoreTable_t *keystore_shadow)
{
    kss_status_t retval = kStatus_KSS_Success;
    if (keystore_shadow != NULL) {
        if (keystore_shadow->magic != KEYSTORE_MAGIC) {
            LOGE(TAG, "Mismatch.keystore_shadow->magic and KEYSTORE_MAGIC");
            retval = kStatus_KSS_Fail;
            goto cleanup;
        }
        if (keystore_shadow->version != KEYSTORE_VERSION) {
            if (keystore_shadow->version == 0x0002) {
                retval = keystore_shadow_From2_To_3(keystore_shadow);
                retval = keystore_shadow_From3_To_4(keystore_shadow);
            }
            else if (keystore_shadow->version == 0x0003) {
                retval = keystore_shadow_From3_To_4(keystore_shadow);
            }
            else {
                LOGE(TAG, " Version mismatch.");
                retval = kStatus_KSS_Fail;
            }
            goto cleanup;
        }
        if (keystore_shadow->maxEntries == 0) {
            LOGE(TAG, "Keystore not yet allocated");
            retval = kStatus_KSS_Fail;
            goto cleanup;
        }
    }
    else {
        retval = kStatus_KSS_Fail;
    }
cleanup:
    return retval;
}
