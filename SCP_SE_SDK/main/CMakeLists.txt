idf_component_register(SRCS "blink_example_main.c"
                            "mqtt_demo_mutual_auth.c"
                            "aws_iot_mbedtls_mqtt.c"
                       INCLUDE_DIRS "."
                       "${CMAKE_CURRENT_LIST_DIR}")
