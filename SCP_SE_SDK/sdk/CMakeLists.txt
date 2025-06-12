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
    REQUIRES 
        driver
        se_mbedtls
    )

    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        KSS_HAVE_MBEDTLS_ALT_KSS=1
        MBEDTLS_ALLOW_PRIVATE_ACCESS=1
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
    target_compile_definitions(se_mbedtls PUBLIC
        KSS_HAVE_MBEDTLS_ALT_KSS=1
        MBEDTLS_ALLOW_PRIVATE_ACCESS=1
    )
endif()

