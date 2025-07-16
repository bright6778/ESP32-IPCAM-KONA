file(GLOB SRC1 "src/*.c")
file(GLOB SRC2 "components/se_mbedtls/*.c")
file(GLOB SRC3 "components/interface/*.c")

message(STATUS "CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}")
if(COMMAND idf_component_register) # ESP-IDF 환경이면
    idf_component_register(
        SRCS ${SRC1} ${SRC2}
    INCLUDE_DIRS 
        "include" 
        "components/se_mbedtls"
    REQUIRES 
        driver
        se_mbedtls
    )

    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        KSS_HAVE_MBEDTLS_ALT_KSS=1
        MBEDTLS_ALLOW_PRIVATE_ACCESS=1
    )
else()  # 일반 CMake 환경이면
    cmake_minimum_required(VERSION 3.10)
    project(ksssdk)
    
    set(
        SRCS ${SRC1} ${SRC2}
    )    
    add_library(ksssdk STATIC ${SRCS})
    message(STATUS "CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}")

    target_include_directories(ksssdk PUBLIC
    	${CMAKE_CURRENT_SOURCE_DIR}/components/se_mbedtls
    	${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_definitions(ksssdk PRIVATE
        KSS_HAVE_MBEDTLS_ALT_KSS=1
        MBEDTLS_ALLOW_PRIVATE_ACCESS=1
    )
endif()

