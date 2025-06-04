idf_component_register(
     SRCS 
          "blink_example_main.c"
          "mqtt_demo_mutual_auth.c"
          "aws_iot_mbedtls_mqtt.c"
          "kss_provisioning.c"
     INCLUDE_DIRS 
          "."
          "${CMAKE_CURRENT_LIST_DIR}"
)

target_include_directories(${COMPONENT_LIB} PUBLIC
    "${CMAKE_SOURCE_DIR}/sdk/components/se_mbedtls"
)

add_compile_options(-I${CMAKE_SOURCE_DIR}/sdk/components/se_mbedtls)

set_property(TARGET mbedtls APPEND PROPERTY
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/sdk/include"
)