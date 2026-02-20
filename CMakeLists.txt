cmake_minimum_required(VERSION 3.10)
project(WiFiVideoReceiver VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

# OpenCV (core, imgproc, dnn)
find_package(OpenCV REQUIRED COMPONENTS core imgproc dnn)
include_directories(${OpenCV_INCLUDE_DIRS})

# SDL2 and its extensions
find_package(SDL2 REQUIRED)
find_package(SDL2_image REQUIRED)
# --- 手动查找 SDL2_ttf 库 ---
find_path(SDL2_TTF_INCLUDE_DIR
    NAMES SDL_ttf.h
    PATH_SUFFIXES SDL2
    PATHS /usr/include /usr/local/include $ENV{SDL2DIR}/include
)
find_library(SDL2_TTF_LIBRARY
    NAMES SDL2_ttf
    PATHS /usr/lib /usr/local/lib $ENV{SDL2DIR}/lib
)
if(NOT SDL2_TTF_LIBRARY OR NOT SDL2_TTF_INCLUDE_DIR)
    message(FATAL_ERROR "Could not find SDL2_ttf library and/or headers. Please install the development package.")
endif()
set(SDL2_TTF_LIBRARIES ${SDL2_TTF_LIBRARY})
set(SDL2_TTF_INCLUDE_DIRS ${SDL2_TTF_INCLUDE_DIR})
message(STATUS "Found SDL2_ttf: ${SDL2_TTF_LIBRARY}")
# --- 手动查找 SDL2_gfx 库 ---
find_path(SDL2_GFX_INCLUDE_DIR
    NAMES SDL2_framerate.h SDL2_gfxPrimitives.h SDL2_imageFilter.h SDL2_rotozoom.h # SDL2_gfx 库的主要头文件
    PATH_SUFFIXES SDL2
    PATHS /usr/include /usr/local/include $ENV{SDL2DIR}/include
)
find_library(SDL2_GFX_LIBRARY
    NAMES SDL2_gfx
    PATHS /usr/lib /usr/local/lib $ENV{SDL2DIR}/lib
)
if(NOT SDL2_GFX_LIBRARY OR NOT SDL2_GFX_INCLUDE_DIR)
    message(FATAL_ERROR "Could not find SDL2_gfx library and/or headers. Please install the development package.")
endif()
set(SDL2_GFX_LIBRARIES ${SDL2_GFX_LIBRARY})
set(SDL2_GFX_INCLUDE_DIRS ${SDL2_GFX_INCLUDE_DIR})
message(STATUS "Found SDL2_gfx: ${SDL2_GFX_LIBRARY}")

include_directories(${SDL2_INCLUDE_DIRS} ${SDL2_IMAGE_INCLUDE_DIRS} ${SDL2_TTF_INCLUDE_DIRS} ${SDL2_GFX_INCLUDE_DIRS})

# libjpeg-turbo
find_path(TURBOJPEG_INCLUDE_DIR turbojpeg.h)
find_library(TURBOJPEG_LIBRARY NAMES turbojpeg)
if(NOT TURBOJPEG_INCLUDE_DIR OR NOT TURBOJPEG_LIBRARY)
    message(FATAL_ERROR "libjpeg-turbo not found")
endif()

# libpcap
find_package(PCAP QUIET)
if(NOT Pcap_FOUND)
    find_library(PCAP_LIBRARY NAMES pcap)
    find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
    if(PCAP_LIBRARY AND PCAP_INCLUDE_DIR)
        set(PCAP_FOUND TRUE)
        set(PCAP_LIBRARIES ${PCAP_LIBRARY})
        set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
    else()
        message(FATAL_ERROR "libpcap not found")
    endif()
endif()

# Subdirectories for your custom libraries
set(SUB_DIRECTORIES
    lib/ESP32_WiFi_Injection_Sinffer
    lib/rs_fec
)
foreach(SUB_DIR ${SUB_DIRECTORIES})
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${SUB_DIR}/CMakeLists.txt)
        add_subdirectory(${SUB_DIR})
    else()
        message(WARNING "CMakeLists.txt not found in: ${SUB_DIR}")
    endif()
endforeach()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/rs_fec/include
    ${CMAKE_SOURCE_DIR}/lib/ESP32_WiFi_Injection_Sinffer/include
    ${TURBOJPEG_INCLUDE_DIR}
)

file(GLOB SRC_FILES src/*.cpp)
add_executable(${PROJECT_NAME} ${SRC_FILES})

target_link_libraries(${PROJECT_NAME}
    ESP32_WiFi_Injection_Sinffer
    rs_fec
    ${PCAP_LIBRARIES}
    ${OpenCV_LIBS}
    ${SDL2_LIBRARIES}
    ${SDL2_IMAGE_LIBRARIES}
    ${SDL2_TTF_LIBRARIES}
    ${SDL2_GFX_LIBRARIES}
    ${TURBOJPEG_LIBRARY}
    Threads::Threads
)