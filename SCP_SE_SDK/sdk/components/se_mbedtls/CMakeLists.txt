idf_component_register(
    SRCS 
        "kss_kose_mbedtls.c"
    INCLUDE_DIRS "." "../../include"
    PRIV_REQUIRES mbedtls
)

# 반드시 이 define을 추가해줘야 mbedTLS가 ALT 코드를 링크함
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    MBEDTLS_ECP_ALT=1
    MBEDTLS_PK_SIGN_ALT=1
    KSS_HAVE_MBEDTLS_ALT_KSS=1
)
