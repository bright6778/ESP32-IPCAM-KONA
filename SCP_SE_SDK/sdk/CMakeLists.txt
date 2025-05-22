idf_component_register(
    SRCS
        "src/debug.c"
        "src/kona_kss_api.c"
        #"src/kona_kss_kose_apis.c"
        "src/kose_APDU_impl.c"
        "src/kose_tlv.c"
        "src/kss_kose_asymmetric.c"
        "src/kss_kose_key_rng.c"
        "src/kss_kose_keyobj.c"
        "src/kss_kose_keystore.c"
        "src/kss_kose_session.c"
        "src/kss_kose_uart.c"
        "src/smartcard.c" 
    INCLUDE_DIRS "include" "components/se_mbedtls"
    REQUIRES driver
    REQUIRES mbedtls
)
