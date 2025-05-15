# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/sdk"
                         "${CMAKE_CURRENT_LIST_DIR}/sdk/components"
                         "$ENV{IDF_PATH}/examples/common_components/protocol_examples_common"
                         "${CMAKE_CURRENT_LIST_DIR}/libraries/backoffAlgorithm"
						 "${CMAKE_CURRENT_LIST_DIR}/libraries/coreMQTT"
						 "${CMAKE_CURRENT_LIST_DIR}/libraries/common/posix_compat")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(SCP_SE_SDK)

target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/root_cert_auth.crt" TEXT)
target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/client.crt" TEXT)
target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/client.key" TEXT)

