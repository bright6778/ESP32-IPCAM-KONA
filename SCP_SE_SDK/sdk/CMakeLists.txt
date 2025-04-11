idf_component_register(
    SRCS
        "src/debug.c"
        "src/kose_APDU_impl.c"
        "src/smartcard.c" 
        "src/kss_kose_uart.c"
        "src/kss_kose_session.c"
    INCLUDE_DIRS "include"
    REQUIRES driver
)
