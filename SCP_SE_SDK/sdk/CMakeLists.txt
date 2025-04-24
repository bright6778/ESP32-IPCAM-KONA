idf_component_register(
    SRCS
        "src/debug.c"
        "src/kona_kss_api.c"
        "src/kose_APDU_impl.c"
        "src/smartcard.c" 
        "src/kss_kose_uart.c"
        "src/kss_kose_session.c"
        "src/kss_kose_mbedtls.c"
    INCLUDE_DIRS "include"
    REQUIRES driver
    REQUIRES mbedtls
)
