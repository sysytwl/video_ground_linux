cmake_minimum_required(VERSION 3.10)
project(esp32_video_rx)

# 检测架构
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(ARCH "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    set(ARCH "x86_64")
else()
    message(FATAL_ERROR "不支持的架构: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

message(STATUS "检测到架构: ${ARCH}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 优化选项
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(ARCH STREQUAL "arm64")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=armv8-a+crypto -mtune=cortex-a53")
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native")
    endif()
endif()

# 包含目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 源文件
file(GLOB SRC_FILES src/*.cpp)

# Libs
set(SUB_DIRECTORIES
    lib/ESP32_WiFi_Injection_Sinffer
    lib/rs_fec
    src
)

foreach(SUB_DIR ${SUB_DIRECTORIES})
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${SUB_DIR}/CMakeLists.txt)
        message(STATUS "Adding subdirectory: ${SUB_DIR}")
        add_subdirectory(${SUB_DIR})
    else()
        message(WARNING "CMakeLists.txt not found in: ${SUB_DIR}")
    endif()
endforeach()



# 查找OpenCV
find_package(OpenCV REQUIRED COMPONENTS core highgui imgproc)

# 对于ARM架构，检查是否有GPU加速库
if(ARCH STREQUAL "arm64")
    find_library(BCM_HOST NAMES bcm_host)
    if(BCM_HOST)
        message(STATUS "找到树莓派GPU库: ${BCM_HOST}")
        set(EXTRA_LIBS ${EXTRA_LIBS} ${BCM_HOST})
    endif()
endif()

# 生成可执行文件
add_executable(esp32_video_rx ${SRC_FILES})

# 链接库
target_link_libraries(esp32_video_rx
    ${OpenCV_LIBS}
    ESP32_WiFi_Injection_Sinffer
    rs_fec
    ${EXTRA_LIBS}
    pthread
)
