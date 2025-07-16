cmake_minimum_required(VERSION 3.10)
project(KSS_SDK_Linux)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 99)
set(DQMiniP ON)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(MBEDTLS_ROOT /home/kona/github/mbedtls)	#사용자의 mbedtls 경로

file(GLOB MBEDTLS_SRC
    /${MBEDTLS_ROOT}/library/*.c
)

include_directories(
	"${MBEDTLS_ROOT}/include"
	"src/include" 
	"src/include/api"
	"ksssdk/include"
	"ksssdk/components/se_mbedtls"
)

add_subdirectory(ksssdk)

set(SOURCE
	src/main.c 
	src/de_sam.c 
	src/aws_iot_mbedtls_mqtt.c 
)

set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -no-pie")

add_executable(KSS_SDK_Linux ${SOURCE} ${MBEDTLS_SRC})

target_link_libraries(KSS_SDK_Linux -L/home/kona/Linux/lvgl/SDK_LVGL_MINIP/target/usr/lib 
    ksssdk 
)
