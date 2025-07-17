# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

if(DEFINED ENV{IDF_PATH}) # ESP-IDF 환경이면
    message(STATUS "ESP-IDF 환경으로 인식됨")

    set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/ksssdk"
                            "${CMAKE_CURRENT_LIST_DIR}/ksssdk/components/se_mbedtls"
                            "$ENV{IDF_PATH}/examples/common_components/protocol_examples_common"
                            "${CMAKE_CURRENT_LIST_DIR}/libraries/backoffAlgorithm"
                            "${CMAKE_CURRENT_LIST_DIR}/libraries/coreMQTT"
                            "${CMAKE_CURRENT_LIST_DIR}/libraries/common/posix_compat")

    add_compile_options(-I${CMAKE_SOURCE_DIR}/ksssdk/components/se_mbedtls)

    include($ENV{IDF_PATH}/tools/cmake/project.cmake)

    project(SCP_SE_SDK)

    target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/root_cert_auth.crt" TEXT)
    target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/root_cert_auth_ecc.crt" TEXT)
    target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/client.crt" TEXT)
    target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/client.key" TEXT)
else()  # 일반 CMake 환경이면
    message(STATUS "일반 CMake 환경으로 인식됨")

    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_C_STANDARD 99)
    project(KSS_SDK_Linux)
    set(DQMiniP ON)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
    set(MBEDTLS_ROOT /home/kona/github/mbedtls)	#사용자의 mbedtls 설치 경로

    file(GLOB MBEDTLS_SRC
        /${MBEDTLS_ROOT}/library/*.c
    )

    include_directories(
        "${MBEDTLS_ROOT}/include"
        "Duali/include" 
        "Duali/include/api"
        "ksssdk/include"
        "ksssdk/components/se_mbedtls"
    )

    add_subdirectory(ksssdk)

    set(SOURCE
        Duali/main.c 
        Duali/de_sam.c 
        Duali/aws_iot_mbedtls_mqtt.c 
    )

    set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -no-pie")

    add_executable(KSS_SDK_Linux ${SOURCE} ${MBEDTLS_SRC})

    target_link_libraries(KSS_SDK_Linux -L/home/kona/Linux/lvgl/SDK_LVGL_MINIP/target/usr/lib 
        ksssdk 
    )
endif()