#idf_component_register(
#    SRCS
#        "src/debug.c"
#        "src/kona_kss_api.c"
#        "src/kona_kss_util_asn1_der.c"
#        "src/kose_APDU_impl.c"
#        "src/kose_tlv.c"
#        "src/kss_kose_asymmetric.c"
#        "src/kss_kose_key_rng.c"
#        "src/kss_kose_keyobj.c"
#        "src/kss_kose_keystore.c"
#        "src/kss_kose_session.c"
#        "src/kss_kose_uart.c"
#        "src/smartcard.c" 
#    INCLUDE_DIRS 
#        "include" 
#        "components/se_mbedtls"
#        #${mbedtls_include}
#    REQUIRES 
#        driver
#        se_mbedtls
#)

if(COMMAND idf_component_register) # ESP-IDF 환경이면
    idf_component_register(
        SRCS
        "src/debug.c"
        "src/kona_kss_api.c"
        "src/kona_kss_util_asn1_der.c"
        "src/kose_APDU_impl.c"
        "src/kose_tlv.c"
        "src/kss_kose_asymmetric.c"
        "src/kss_kose_key_rng.c"
        "src/kss_kose_keyobj.c"
        "src/kss_kose_keystore.c"
        "src/kss_kose_session.c"
        "src/kss_kose_uart.c"
        "src/smartcard.c" 
    INCLUDE_DIRS 
        "include" 
        "components/se_mbedtls"
        #${mbedtls_include}
    REQUIRES 
        driver
        se_mbedtls
    )

    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        KSS_HAVE_MBEDTLS_ALT_KSS=1
        MBEDTLS_ALLOW_PRIVATE_ACCESS=1
        MBEDTLS_CONFIG_FILE="mbedtls_config.h"
    )
else()  # 일반 CMake 환경이면
    add_library(se_mbedtls STATIC
        "src/debug.c"
        "src/kona_kss_api.c"
        "src/kona_kss_util_asn1_der.c"
        "src/kose_APDU_impl.c"
        "src/kose_tlv.c"
        "src/kss_kose_asymmetric.c"
        "src/kss_kose_key_rng.c"
        "src/kss_kose_keyobj.c"
        "src/kss_kose_keystore.c"
        "src/kss_kose_session.c"
        "src/kss_kose_uart.c"
        "src/smartcard.c" 
    )
    #target_include_directories(
    #    se_mbedtls PUBLIC 
    #    ${CMAKE_CURRENT_LIST_DIR}/include
    #)
    target_compile_definitions(se_mbedtls PUBLIC
        KSS_HAVE_MBEDTLS_ALT_KSS=1
        MBEDTLS_ALLOW_PRIVATE_ACCESS=1
        MBEDTLS_CONFIG_FILE="se_mbedtls/mbedtls_config.h"
    )
    #target_link_libraries(${COMPONENT_LIB} PUBLIC
    #    driver
    #    se_mbedtls
    #)
endif()

#set(EXTRA_COMPONENT_DIRS ${CMAKE_CURRENT_LIST_DIR}/components)

target_compile_options(${COMPONENT_LIB} PUBLIC
    -DMBEDTLS_CONFIG_FILE="mbedtls_config.h"
)

# 반드시 이 define을 추가해줘야 mbedTLS가 ALT 코드를 링크함
#target_compile_definitions(${COMPONENT_LIB} PRIVATE
#    KSS_HAVE_MBEDTLS_ALT_KSS=1
#    MBEDTLS_ALLOW_PRIVATE_ACCESS=1
#    MBEDTLS_CONFIG_FILE="mbedtls_config.h"
#)

