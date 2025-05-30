idf_component_register(
     SRCS 
          "blink_example_main.c"
          "mqtt_demo_mutual_auth.c"
          "aws_iot_mbedtls_mqtt.c"
     INCLUDE_DIRS 
          "."
          "${CMAKE_CURRENT_LIST_DIR}"
)

target_compile_options(${COMPONENT_LIB} PUBLIC
    -DMBEDTLS_CONFIG_FILE="mbedtls_config.h"
)

#target_compile_definitions(${COMPONENT_LIB} PUBLIC
    #MBEDTLS_CONFIG_FILE="mbedtls_config.h"
#)

target_include_directories(${COMPONENT_LIB} PUBLIC
    "${CMAKE_SOURCE_DIR}/sdk/components/se_mbedtls"
)

add_compile_options(-I${CMAKE_SOURCE_DIR}/sdk/components/se_mbedtls)

set_property(TARGET mbedtls APPEND PROPERTY
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/sdk/include"
)