/*
 *
 * Copyright 2018-2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#ifndef KSS_APIS_INC_KONA_KSS_FTR_H_
#define KSS_APIS_INC_KONA_KSS_FTR_H_

/* Define ALT functions. */
#define MBEDTLS_ECP_ALT
#define MBEDTLS_RSA_ALT

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* clang-format off */


/* # CMake Features : Start */


/** PTMW_Applet : The Secure Element Applet
 *
 * You can compile host library for different Applets listed below.
 * Please note, some of these Applets may be for NXP Internal use only.
 */

/** Compiling without any Applet Support */
#define KSS_HAVE_APPLET_NONE 0

/** KOSE Type A (ECC) */
#define KSS_HAVE_APPLET_KOSE_A 0

/** KOSE Type B (RSA) */
#define KSS_HAVE_APPLET_KOSE_B 0

/** KOSE (Super set of A + B) */
#define KSS_HAVE_APPLET_KOSE_C 1

/** SE051UWB (Similar to SE05x) */
#define KSS_HAVE_APPLET_SE051_UWB 0

/** SE051 with SPAKE Support */
#define KSS_HAVE_APPLET_SE051_H 0

/** AUTH */
#define KSS_HAVE_APPLET_AUTH 0

/** KOSEE */
#define KSS_HAVE_APPLET_KOSE_E 0

/** NXP Internal testing Applet */
#define KSS_HAVE_APPLET_LOOPBACK 0

#if (( 0                             \
    + KSS_HAVE_APPLET_NONE           \
    + KSS_HAVE_APPLET_KOSE_A        \
    + KSS_HAVE_APPLET_KOSE_B        \
    + KSS_HAVE_APPLET_KOSE_C        \
    + KSS_HAVE_APPLET_SE051_UWB      \
    + KSS_HAVE_APPLET_SE051_H        \
    + KSS_HAVE_APPLET_AUTH           \
    + KSS_HAVE_APPLET_KOSE_E        \
    + KSS_HAVE_APPLET_LOOPBACK       \
    ) > 1)
#        error "Enable only one of 'PTMW_Applet'"
#endif


#if (( 0                             \
    + KSS_HAVE_APPLET_NONE           \
    + KSS_HAVE_APPLET_KOSE_A        \
    + KSS_HAVE_APPLET_KOSE_B        \
    + KSS_HAVE_APPLET_KOSE_C        \
    + KSS_HAVE_APPLET_SE051_UWB      \
    + KSS_HAVE_APPLET_SE051_H        \
    + KSS_HAVE_APPLET_AUTH           \
    + KSS_HAVE_APPLET_KOSE_E        \
    + KSS_HAVE_APPLET_LOOPBACK       \
    ) == 0)
#        error "Enable at-least one of 'PTMW_Applet'"
#endif



/** KOSE Applet version.
 *
 */

/** KOSE */
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define KOSE_APPLET_VERSION_MAJOR    1
#define KOSE_APPLET_VERSION_MINOR    0
#define KOSE_APPLET_VERSION_PATCH    0
#define KOSE_APPLET_VERSION_STRING   STR(KOSE_APPLET_VERSION_MAJOR) "." STR(KOSE_APPLET_VERSION_MINOR) "." STR(KOSE_APPLET_VERSION_PATCH)

/** PTMW_HostCrypto : Counterpart Crypto on Host
 *
 * What is being used as a cryptographic library on the host.
 * As of now only OpenSSL / mbedTLS is supported
 */

/** Use mbedTLS as host crypto */
#define KSS_HAVE_HOSTCRYPTO_MBEDTLS 1

/** Use OpenSSL as host crypto */
#define KSS_HAVE_HOSTCRYPTO_OPENSSL 0

/** User Implementation of Host Crypto
 * e.g. Files at ``sss/src/user/crypto`` have low level AES/CMAC primitives.
 * The files at ``sss/src/user`` use those primitives.
 * This becomes an example for users with their own AES Implementation
 * This then becomes integration without mbedTLS/OpenSSL for SCP03 / AESKey.
 *
 * .. note:: ECKey abstraction is not implemented/available yet. */
#define KSS_HAVE_HOSTCRYPTO_USER 0

/** NO Host Crypto
 * Note, this is unsecure and only provided for experimentation
 * on platforms that do not have an mbedTLS PORT
 * Many :ref:`sssftr-control` have to be disabled to have a valid build. */
#define KSS_HAVE_HOSTCRYPTO_NONE 0

#if (( 0                             \
    + KSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    + KSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + KSS_HAVE_HOSTCRYPTO_USER       \
    + KSS_HAVE_HOSTCRYPTO_NONE       \
    ) > 1)
#        error "Enable only one of 'PTMW_HostCrypto'"
#endif


#if (( 0                             \
    + KSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    + KSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + KSS_HAVE_HOSTCRYPTO_USER       \
    + KSS_HAVE_HOSTCRYPTO_NONE       \
    ) == 0)
#        error "Enable at-least one of 'PTMW_HostCrypto'"
#endif



/** PTMW_mbedTLS_ALT : ALT Engine implementation for mbedTLS
 *
 * When set to None, mbedTLS would not use ALT Implementation to connect to / use Secure Element.
 * This needs to be set to KSS for Cloud Demos over KSS APIs
 */

/** Use KSS Layer ALT implementation */
#define KSS_HAVE_MBEDTLS_ALT_KSS 1

/** Enable TF-M based on PSA as ALT */
#define KSS_HAVE_MBEDTLS_ALT_PSA 0

/** Not using any mbedTLS_ALT
 *
 * When this is selected, cloud demos can not work with mbedTLS */
#define KSS_HAVE_MBEDTLS_ALT_NONE 0

#if (( 0                             \
    + KSS_HAVE_MBEDTLS_ALT_KSS       \
    + KSS_HAVE_MBEDTLS_ALT_PSA       \
    + KSS_HAVE_MBEDTLS_ALT_NONE      \
    ) > 1)
#        error "Enable only one of 'PTMW_mbedTLS_ALT'"
#endif


#if (( 0                             \
    + KSS_HAVE_MBEDTLS_ALT_KSS       \
    + KSS_HAVE_MBEDTLS_ALT_PSA       \
    + KSS_HAVE_MBEDTLS_ALT_NONE      \
    ) == 0)
#        error "Enable at-least one of 'PTMW_mbedTLS_ALT'"
#endif



/** PTMW_SCP : Secure Channel Protocol
 *
 * In case we enable secure channel to Secure Element, which interface to be used.
 */

/**  */
#define KSS_HAVE_SCP_NONE 0

/** Use KSS Layer for SCP.  Used for KOSE family. */
#define KSS_HAVE_SCP_SCP03_KSS 1

#if (( 0                             \
    + KSS_HAVE_SCP_NONE              \
    + KSS_HAVE_SCP_SCP03_KSS         \
    ) > 1)
#        error "Enable only one of 'PTMW_SCP'"
#endif


#if (( 0                             \
    + KSS_HAVE_SCP_NONE              \
    + KSS_HAVE_SCP_SCP03_KSS         \
    ) == 0)
#        error "Enable at-least one of 'PTMW_SCP'"
#endif



/** PTMW_FIPS : Enable or disable FIPS
 *
 * This selection mostly impacts tests, and generally not the actual Middleware
 */

/** NO FIPS */
#define KSS_HAVE_FIPS_NONE 1

/** KOSE IC FIPS */
#define KSS_HAVE_FIPS_KOSE 0

/** FIPS 140-2 */
#define KSS_HAVE_FIPS_140_2 0

/** FIPS 140-3 */
#define KSS_HAVE_FIPS_140_3 0

#if (( 0                             \
    + KSS_HAVE_FIPS_NONE             \
    + KSS_HAVE_FIPS_KOSE            \
    + KSS_HAVE_FIPS_140_2            \
    + KSS_HAVE_FIPS_140_3            \
    ) > 1)
#        error "Enable only one of 'PTMW_FIPS'"
#endif


#if (( 0                             \
    + KSS_HAVE_FIPS_NONE             \
    + KSS_HAVE_FIPS_KOSE            \
    + KSS_HAVE_FIPS_140_2            \
    + KSS_HAVE_FIPS_140_3            \
    ) == 0)
#        error "Enable at-least one of 'PTMW_FIPS'"
#endif



/** PTMW_SBL : Enable/Disable SBL Bootable support
 *
 * This option is to enable/disable boot from SBL by switching linker address
 */

/** Not SBL bootable */
#define KSS_HAVE_SBL_NONE 1

/** KOSE based LPC55S SBL bootable */
#define KSS_HAVE_SBL_SBL_LPC55S 0

#if (( 0                             \
    + KSS_HAVE_SBL_NONE              \
    + KSS_HAVE_SBL_SBL_LPC55S        \
    ) > 1)
#        error "Enable only one of 'PTMW_SBL'"
#endif


#if (( 0                             \
    + KSS_HAVE_SBL_NONE              \
    + KSS_HAVE_SBL_SBL_LPC55S        \
    ) == 0)
#        error "Enable at-least one of 'PTMW_SBL'"
#endif



/** PTMW_KOSE_Auth : KOSE Authentication
 *
 * This settings is used by examples to connect using various options
 * to authenticate with the Applet.
 * The KOSE_Auth options can be changed for KSDK Demos and Examples.
 * To change KOSE_Auth option follow below steps.
 * Set flag ``KSS_HAVE_SCP_SCP03_KSS`` to 1 and Reset flag ``KSS_HAVE_SCP_NONE`` to 0.
 * To change KOSE_Auth option other than ``None`` and  ``PlatfSCP03``,
 * execute se05x_Delete_and_test_provision.exe in order to provision the Authentication Key.
 * To change KOSE_Auth option to ``ECKey`` or ``ECKey_PlatfSCP03``,
 * Set additional flag ``KSS_HAVE_HOSTCRYPTO_ANY`` to 1.
 */

/** Use the default session (i.e. session less) login */
#define KSS_HAVE_KOSE_AUTH_NONE 1

/** Do User Authentication with UserID */
#define KSS_HAVE_KOSE_AUTH_USERID 0

/** Use Platform SCP for connection to SE */
#define KSS_HAVE_KOSE_AUTH_PLATFSCP03 0

/** Do User Authentication with AES Key
 * Earlier this was called AppletSCP03 */
#define KSS_HAVE_KOSE_AUTH_AESKEY 0

/** Do User Authentication with EC Key
 * Earlier this was called FastSCP */
#define KSS_HAVE_KOSE_AUTH_ECKEY 0

/** UserID and PlatfSCP03 */
#define KSS_HAVE_KOSE_AUTH_USERID_PLATFSCP03 0

/** AESKey and PlatfSCP03 */
#define KSS_HAVE_KOSE_AUTH_AESKEY_PLATFSCP03 0

/** ECKey and PlatfSCP03 */
#define KSS_HAVE_KOSE_AUTH_ECKEY_PLATFSCP03 0

#if (( 0                             \
    + KSS_HAVE_KOSE_AUTH_NONE       \
    + KSS_HAVE_KOSE_AUTH_USERID     \
    + KSS_HAVE_KOSE_AUTH_PLATFSCP03 \
    + KSS_HAVE_KOSE_AUTH_AESKEY     \
    + KSS_HAVE_KOSE_AUTH_ECKEY      \
    + KSS_HAVE_KOSE_AUTH_USERID_PLATFSCP03 \
    + KSS_HAVE_KOSE_AUTH_AESKEY_PLATFSCP03 \
    + KSS_HAVE_KOSE_AUTH_ECKEY_PLATFSCP03 \
    ) > 1)
#        error "Enable only one of 'PTMW_KOSE_Auth'"
#endif


#if (( 0                             \
    + KSS_HAVE_KOSE_AUTH_NONE       \
    + KSS_HAVE_KOSE_AUTH_USERID     \
    + KSS_HAVE_KOSE_AUTH_PLATFSCP03 \
    + KSS_HAVE_KOSE_AUTH_AESKEY     \
    + KSS_HAVE_KOSE_AUTH_ECKEY      \
    + KSS_HAVE_KOSE_AUTH_USERID_PLATFSCP03 \
    + KSS_HAVE_KOSE_AUTH_AESKEY_PLATFSCP03 \
    + KSS_HAVE_KOSE_AUTH_ECKEY_PLATFSCP03 \
    ) == 0)
#        error "Enable at-least one of 'PTMW_KOSE_Auth'"
#endif



/** PTMW_OpenSSL : For PC, which OpenSSL to pick up
 *
 * On Linux based builds, this option has no impact, because the build system
 * picks up the default available/installed OpenSSL from the system directly.
 */

/** Use 1.1.1 version (Only applicable on PC) */
#define KSS_HAVE_OPENSSL_1_1_1 1

/** Use 3.0 version (Only applicable on PC) */
#define KSS_HAVE_OPENSSL_3_0 0

#if (( 0                             \
    + KSS_HAVE_OPENSSL_1_1_1         \
    + KSS_HAVE_OPENSSL_3_0           \
    ) > 1)
#        error "Enable only one of 'PTMW_OpenSSL'"
#endif


#if (( 0                             \
    + KSS_HAVE_OPENSSL_1_1_1         \
    + KSS_HAVE_OPENSSL_3_0           \
    ) == 0)
#        error "Enable at-least one of 'PTMW_OpenSSL'"
#endif


/* ====================================================================== *
 * == Feature selection/values ========================================== *
 * ====================================================================== */


/** KOSE Secure Element : Symmetric AES */
#define KSSFTR_KOSE_AES 1

/** KOSE Secure Element : Elliptic Curve Cryptography */
#define KSSFTR_KOSE_ECC 1

/** KOSE Secure Element : RSA */
#define KSSFTR_KOSE_RSA 1

/** KOSE Secure Element : KEY operations : SET Key */
#define KSSFTR_KOSE_KEY_SET 1

/** KOSE Secure Element : KEY operations : GET Key */
#define KSSFTR_KOSE_KEY_GET 1

/** KOSE Secure Element : Authenticate via ECKey */
#define KSSFTR_KOSE_AuthECKey 0

/** KOSE Secure Element : Symmetric DES */
#define KSSFTR_KOSE_DES 1

/** KOSE Secure Element : Allow creation of user/authenticated session.
 *
 * If the intended deployment only uses Platform SCP
 * Or it is a pure session less integration, this can
 * save some code size. */
#define KSSFTR_KOSE_AuthSession 0

/** KOSE Secure Element : Allow creation/deletion of Crypto Objects
 *
 * If disabled, new Crytpo Objects are neither created and
 * old/existing Crypto Objects are not deleted.
 * It is assumed that during provisioning phase, the required
 * Crypto Objects are pre-created or they are never going to
 * be needed. */
#define KSSFTR_KOSE_CREATE_DELETE_CRYPTOOBJ 1

/** Software : Symmetric AES */
#define KSSFTR_SW_AES 1

/** Software : Elliptic Curve Cryptography */
#define KSSFTR_SW_ECC 1

/** Software : RSA */
#define KSSFTR_SW_RSA 1

/** Software : KEY operations : SET Key */
#define KSSFTR_SW_KEY_SET 1

/** Software : KEY operations : GET Key */
#define KSSFTR_SW_KEY_GET 1

/** Software : Used as a test counterpart
 *
 * e.g. Major part of the mebdTLS KSS layer is purely used for
 * testing of Secure Element implementation, and can be avoided
 * fully during many production scenarios. */
#define KSSFTR_SW_TESTCOUNTERPART 1

/* ====================================================================== *
 * == Computed Options ================================================== *
 * ====================================================================== */

/** Symmetric AES */
#define KSSFTR_AES               (KSSFTR_KOSE_AES + KSSFTR_SW_AES)
/** Elliptic Curve Cryptography */
#define KSSFTR_ECC               (KSSFTR_KOSE_ECC + KSSFTR_SW_ECC)
/** RSA */
#define KSSFTR_RSA               (KSSFTR_KOSE_RSA + KSSFTR_SW_RSA)
/** KEY operations : SET Key */
#define KSSFTR_KEY_SET           (KSSFTR_KOSE_KEY_SET + KSSFTR_SW_KEY_SET)
/** KEY operations : GET Key */
#define KSSFTR_KEY_GET           (KSSFTR_KOSE_KEY_GET + KSSFTR_SW_KEY_GET)
/** KEY operations */
#define KSSFTR_KEY               (KSSFTR_KEY_SET + KSSFTR_KEY_GET)
/** KEY operations */
#define KSSFTR_KOSE_KEY         (KSSFTR_KOSE_KEY_SET + KSSFTR_KOSE_KEY_GET)
/** KEY operations */
#define KSSFTR_SW_KEY            (KSSFTR_SW_KEY_SET + KSSFTR_SW_KEY_GET)


#define KSS_HAVE_APPLET \
 (KSS_HAVE_APPLET_KOSE_A | KSS_HAVE_APPLET_KOSE_B | KSS_HAVE_APPLET_KOSE_C | KSS_HAVE_APPLET_SE051_UWB | KSS_HAVE_APPLET_SE051_H | KSS_HAVE_APPLET_AUTH | KSS_HAVE_APPLET_KOSE_E | KSS_HAVE_APPLET_LOOPBACK)

#define KSS_HAVE_APPLET_KOSE_IOT \
 (KSS_HAVE_APPLET_KOSE_A | KSS_HAVE_APPLET_KOSE_B | KSS_HAVE_APPLET_KOSE_C | KSS_HAVE_APPLET_SE051_UWB | KSS_HAVE_APPLET_SE051_H | KSS_HAVE_APPLET_AUTH | KSS_HAVE_APPLET_KOSE_E)

#define KSS_HAVE_MBEDTLS_ALT \
 (KSS_HAVE_MBEDTLS_ALT_KSS | KSS_HAVE_MBEDTLS_ALT_PSA)

#define KSS_HAVE_HOSTCRYPTO_ANY \
 (KSS_HAVE_HOSTCRYPTO_MBEDTLS | KSS_HAVE_HOSTCRYPTO_OPENSSL | KSS_HAVE_HOSTCRYPTO_USER)

#define KSS_HAVE_FIPS \
 (KSS_HAVE_FIPS_KOSE | KSS_HAVE_FIPS_140_2 | KSS_HAVE_FIPS_140_3)

/* # CMake Features : END */

/* ========= Miscellaneous values : START =================== */

/* ECC Mode is available */
#define KSS_HAVE_ECC 1

/* RSA is available */
#define KSS_HAVE_RSA 1

/* Edwards Curve is enabled */
#define KSS_HAVE_EC_ED 1

/* Montgomery Curve is enabled */
#define KSS_HAVE_EC_MONT 1

/* MIFARE DESFire is enabled */
#define KSS_HAVE_MIFARE_DESFIRE 1

/* PBKDF2 is enabled */
#define KSS_HAVE_PBKDF2 1

/* TLS handshake support on SE is enabled */
#define KSS_HAVE_TLS_HANDSHAKE 1

/* Import Export Key is enabled */
#define KSS_HAVE_IMPORT 1

/* With NXP NFC Reader Library */
#define KSS_HAVE_NXPNFCRDLIB 0

/* For backwards compatibility */
#define KSS_HAVE_TESTCOUNTERPART (KSSFTR_SW_TESTCOUNTERPART)

/* ========= Miscellaneous values : END ===================== */

/* Enable one of these
 * If none is selected, default config would be used
 */
#define KSS_PFSCP_ENABLE_KOSEA1 0
#define KSS_PFSCP_ENABLE_KOSEA2 0
#define KSS_PFSCP_ENABLE_KOSEB1 0
#define KSS_PFSCP_ENABLE_KOSEB2 0
#define KSS_PFSCP_ENABLE_KOSEC1 0
#define KSS_PFSCP_ENABLE_KOSEC2 0
#define KSS_PFSCP_ENABLE_KOSE_DEVKIT 0
#define KSS_PFSCP_ENABLE_SE051A2 0
#define KSS_PFSCP_ENABLE_SE051C2 0
#define KSS_PFSCP_ENABLE_KOSEF2 0
#define KSS_PFSCP_ENABLE_SE051C_0005A8FA 0
#define KSS_PFSCP_ENABLE_SE051A_0001A920 0
#define KSS_PFSCP_ENABLE_KOSEE_0001A921 0
#define KSS_PFSCP_ENABLE_SE051W_0005A739 0
#define KSS_PFSCP_ENABLE_A5000_0004A736 0
#define KSS_PFSCP_ENABLE_KOSEF2_0001A92A 0
#define KSS_PFSCP_ENABLE_SE052_B501 0
#define KSS_PFSCP_ENABLE_OTHER 0

/* ========= Calculated values : START ====================== */

/* Should we expose, KSS APIs */
#define KSS_HAVE_KSS ( 0             \
    + KSS_HAVE_APPLET_KOSE_IOT      \
    + KSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + KSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    + KSS_HAVE_HOSTCRYPTO_USER       \
    )

#if KSS_HAVE_HOSTCRYPTO_NONE
#   undef  KSSFTR_KOSE_AuthSession
#   define KSSFTR_KOSE_AuthSession 0
#endif

/* Montgomery curves is not supported in KOSE_A */
#if KSS_HAVE_APPLET_KOSE_A
#       undef KSS_HAVE_EC_MONT
#       define KSS_HAVE_EC_MONT 0
    /* ED is not supported in KOSE_A */
#    if KSS_HAVE_KOSE_VER_03_XX
#       undef KSS_HAVE_EC_ED
#       define KSS_HAVE_EC_ED 0
#    endif // KSS_HAVE_KOSE_VER_03_XX
#endif // KSS_HAVE_APPLET_KOSE_A

#if KSS_HAVE_RSA
#    if KSS_HAVE_APPLET_SE051_UWB
#       define KSS_HAVE_RSA_4K 0
#    else
#       define KSS_HAVE_RSA_4K 1
#    endif // KSS_HAVE_APPLET_SE051_UWB
#endif // KSS_HAVE_RSA


#if KSS_HAVE_ECC
#   define KSS_HAVE_EC_NIST_192 0
#   define KSS_HAVE_EC_NIST_224 0
#   define KSS_HAVE_EC_NIST_256 1
#   define KSS_HAVE_EC_NIST_384 0
#   define KSS_HAVE_EC_NIST_521 0
#   define KSS_HAVE_EC_BP 0
#   define KSS_HAVE_EC_NIST_K 0
#   define KSS_HAVE_EDDSA 1
#   if KSS_HAVE_APPLET_KOSE_A
#      undef KSS_HAVE_EDDSA
#      define KSS_HAVE_EDDSA 0
#   endif // KSS_HAVE_APPLET_KOSE_A
#   if KSS_HAVE_APPLET_AUTH
#      undef KSS_HAVE_EC_NIST_192
#      undef KSS_HAVE_EC_NIST_224
#      undef KSS_HAVE_EC_NIST_521
#      undef KSS_HAVE_EC_BP
#      undef KSS_HAVE_EC_NIST_K
#      undef KSS_HAVE_EDDSA
#      define KSS_HAVE_EC_NIST_192 0
#      define KSS_HAVE_EC_NIST_224 0
#      define KSS_HAVE_EC_NIST_521 0
#      define KSS_HAVE_EC_BP 0
#      define KSS_HAVE_EC_NIST_K 0
#      define KSS_HAVE_EDDSA 0
#   endif // KSS_HAVE_APPLET_AUTH
#endif // KSS_HAVE_ECC

#if KSS_HAVE_APPLET
#    if KSS_HAVE_APPLET_AUTH
#       define KSS_HAVE_HASH_1 0
#       define KSS_HAVE_HASH_224 0
#       define KSS_HAVE_HASH_512 0
#    else
#       define KSS_HAVE_HASH_1 1
#       define KSS_HAVE_HASH_224 1
#       define KSS_HAVE_HASH_512 1
#    endif // KSS_HAVE_APPLET_AUTH
#    if KSS_HAVE_APPLET_KOSE_E
#       undef KSS_HAVE_RSA
#       define KSS_HAVE_RSA 0
#    endif //KSS_HAVE_APPLET_KOSE_E
#    if KSS_HAVE_RSA
#        if KSS_HAVE_APPLET_SE051_H
#           undef KSS_HAVE_RSA_4K
#           define KSS_HAVE_RSA_4K 0
#           define KSS_HAVE_RSA_3K 0
#        else
#        define KSS_HAVE_RSA_3K 1
#        endif //KSS_HAVE_APPLET_SE051_H
#    endif //KSS_HAVE_RSA
#endif



/* ========= Calculated values : END ======================== */

/* clang-format on */

#endif /* KSS_APIS_INC_KONA_KSS_FTR_H_ */
