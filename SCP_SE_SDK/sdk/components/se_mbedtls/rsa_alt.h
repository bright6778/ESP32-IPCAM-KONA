/**
 * \file rsa.h
 *
 * \brief This file provides an API for the RSA public-key cryptosystem.
 *
 * The RSA public-key cryptosystem is defined in <em>Public-Key
 * Cryptography Standards (PKCS) #1 v1.5: RSA Encryption</em>
 * and <em>Public-Key Cryptography Standards (PKCS) #1 v2.1:
 * RSA Cryptography Specifications</em>.
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  Copyright (C) 2019, NXP, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#if defined(KSS_USE_FTR_FILE)
#include "kona_kss_ftr.h"
#else
#include "kona_kss_ftr_default.h"
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_RSA_ALT)
#include "mbedtls/pk.h"
#include "kona_kss_api.h"
//#include "kss_kose_mbedtls.h"


/* clang-format off */
#if 0 //NXP
typedef struct
{
    int ver;                    /*!<  Reserved for internal purposes.
                                 *    Do not set this field in application
                                 *    code. Its meaning might change without
                                 *    notice. */
    size_t len;                 /*!<  The size of \p N in Bytes. */

    mbedtls_mpi N;              /*!<  The public modulus. */
    mbedtls_mpi E;              /*!<  The public exponent. */

    mbedtls_mpi D;              /*!<  The private exponent. */
    mbedtls_mpi P;              /*!<  The first prime factor. */
    mbedtls_mpi Q;              /*!<  The second prime factor. */

    mbedtls_mpi DP;             /*!<  <code>D % (P - 1)</code>. */
    mbedtls_mpi DQ;             /*!<  <code>D % (Q - 1)</code>. */
    mbedtls_mpi QP;             /*!<  <code>1 / (Q % P)</code>. */

    mbedtls_mpi RN;             /*!<  cached <code>R^2 mod N</code>. */

    mbedtls_mpi RP;             /*!<  cached <code>R^2 mod P</code>. */
    mbedtls_mpi RQ;             /*!<  cached <code>R^2 mod Q</code>. */

    mbedtls_mpi Vi;             /*!<  The cached blinding value. */
    mbedtls_mpi Vf;             /*!<  The cached un-blinding value. */

    int padding;                /*!< Selects padding mode:
                                     #MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
                                     #MBEDTLS_RSA_PKCS_V21 for OAEP or PSS. */
    int hash_id;                /*!< Hash identifier of mbedtls_md_type_t type,
                                     as specified in md.h for use in the MGF
                                     mask generating function used in the
                                     EME-OAEP and EMSA-PSS encodings. */
#if defined(MBEDTLS_THREADING_C)
    /* Invariant: the mutex is initialized iff ver != 0. */
    mbedtls_threading_mutex_t mutex;    /*!<  Thread-safety mutex. */
#endif

    /** Reference to object mapped between KSS Layer        */
    kss_object_t *pKSSObject;
} mbedtls_rsa_context;
#endif //NXP

typedef struct mbedtls_rsa_context {
    int MBEDTLS_PRIVATE(ver);                    /*!<  Reserved for internal purposes.
                                                  *    Do not set this field in application
                                                  *    code. Its meaning might change without
                                                  *    notice. */
    size_t MBEDTLS_PRIVATE(len);                 /*!<  The size of \p N in Bytes. */

    mbedtls_mpi MBEDTLS_PRIVATE(N);              /*!<  The public modulus. */
    mbedtls_mpi MBEDTLS_PRIVATE(E);              /*!<  The public exponent. */

    mbedtls_mpi MBEDTLS_PRIVATE(D);              /*!<  The private exponent. */
    mbedtls_mpi MBEDTLS_PRIVATE(P);              /*!<  The first prime factor. */
    mbedtls_mpi MBEDTLS_PRIVATE(Q);              /*!<  The second prime factor. */

    mbedtls_mpi MBEDTLS_PRIVATE(DP);             /*!<  <code>D % (P - 1)</code>. */
    mbedtls_mpi MBEDTLS_PRIVATE(DQ);             /*!<  <code>D % (Q - 1)</code>. */
    mbedtls_mpi MBEDTLS_PRIVATE(QP);             /*!<  <code>1 / (Q % P)</code>. */

    mbedtls_mpi MBEDTLS_PRIVATE(RN);             /*!<  cached <code>R^2 mod N</code>. */

    mbedtls_mpi MBEDTLS_PRIVATE(RP);             /*!<  cached <code>R^2 mod P</code>. */
    mbedtls_mpi MBEDTLS_PRIVATE(RQ);             /*!<  cached <code>R^2 mod Q</code>. */

    mbedtls_mpi MBEDTLS_PRIVATE(Vi);             /*!<  The cached blinding value. */
    mbedtls_mpi MBEDTLS_PRIVATE(Vf);             /*!<  The cached un-blinding value. */

    int MBEDTLS_PRIVATE(padding);                /*!< Selects padding mode:
                                                  #MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
                                                  #MBEDTLS_RSA_PKCS_V21 for OAEP or PSS. */
    int MBEDTLS_PRIVATE(hash_id);                /*!< Hash identifier of mbedtls_md_type_t type,
                                                    as specified in md.h for use in the MGF
                                                    mask generating function used in the
                                                    EME-OAEP and EMSA-PSS encodings. */
#if defined(MBEDTLS_THREADING_C)
    /* Invariant: the mutex is initialized iff ver != 0. */
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);    /*!<  Thread-safety mutex. */
#endif
    /** Reference to object mapped between KSS Layer        */
    kss_object_t *pKSSObject;
}
mbedtls_rsa_context;

/* clang-format on */

#endif /* MBEDTLS_RSA_ALT */
