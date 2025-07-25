idf_component_register(
     SRCS 
          "blink_example_main.c"
          "aws_iot_mbedtls_mqtt.c"
          "gen_csr.c"
          "kss_provisioning.c"
     INCLUDE_DIRS 
          "."
          "${CMAKE_CURRENT_LIST_DIR}"

)

target_include_directories(${COMPONENT_LIB} PUBLIC
    "${CMAKE_SOURCE_DIR}/ksssdk/components/se_mbedtls"
    "${CMAKE_SOURCE_DIR}/ksssdk/components/tsm-agent/include"
    "${CMAKE_SOURCE_DIR}/ksssdk/components/tsm-agent/src"
    PRIV_REQUIRES 
        esp_http_client
        esp-tls
        json
        driver
)

add_compile_options(-I${CMAKE_SOURCE_DIR}/ksssdk/components/se_mbedtls)

set_property(TARGET mbedtls APPEND PROPERTY
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/ksssdk/include"
)