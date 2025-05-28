idf_component_register(
    SRCS
        "ecdh_alt.c"
        "ecdsa_verify_alt.c"
        "kss_kose_mbedtls.c"
        "keystore_cmn.c"
    INCLUDE_DIRS "." "../../include"
    REQUIRES mbedtls
)

#target_compile_options(${COMPONENT_LIB} PUBLIC
#    -DMBEDTLS_CONFIG_FILE="mbedtls_config.h"
#)

# 반드시 이 define을 추가해줘야 mbedTLS가 ALT 코드를 링크함
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    KSS_HAVE_MBEDTLS_ALT_KSS=1
    MBEDTLS_PK_C=1
    MBEDTLS_ECP_C=1
    #MBEDTLS_ECP_ALT=1
    #MBEDTLS_ECDSA_SIGN_ALT=1
    MBEDTLS_ECDSA_VERIFY_ALT=1
    MBEDTLS_ECDH_LEGACY_CONTEXT=1
    MBEDTLS_ALLOW_PRIVATE_ACCESS=1
    MBEDTLS_CONFIG_FILE="mbedtls_config.h"
)

target_include_directories(${COMPONENT_LIB} INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)