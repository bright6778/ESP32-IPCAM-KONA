idf_component_register(
    SRCS
        "src/*.c"
       
    INCLUDE_DIRS 
        "include" 
        "."
    REQUIRES mbedtls
    PRIV_REQUIRES 
        esp_http_client
        esp-tls
        json
        driver    
)

# 반드시 이 define을 추가해줘야 mbedTLS가 ALT 코드를 링크함
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    KSS_HAVE_MBEDTLS_ALT_KSS=1
    MBEDTLS_ECDH_LEGACY_CONTEXT=1
    MBEDTLS_ALLOW_PRIVATE_ACCESS=1
)

target_include_directories(${COMPONENT_LIB} INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)