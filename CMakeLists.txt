cmake_minimum_required(VERSION 3.10)
project(WiFiVideoReceiver VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find required packages
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

find_package(OpenCV REQUIRED) # Find OpenCV
include_directories(${OpenCV_INCLUDE_DIRS})

find_package(SDL2 REQUIRED)#SDL2
include_directories(${SDL2_INCLUDE_DIRS})

pkg_check_modules(FFMPEG REQUIRED IMPORTED_TARGET
    libavformat
    libavcodec
    libavutil
    libavfilter
    libswscale
)
find_package(PCAP QUIET)
if(NOT Pcap_FOUND)
    # Option 2: Manual search if the module fails
    message(STATUS "Module not found, searching for libraries and headers...")
    find_library(PCAP_LIBRARY NAMES pcap PATH /usr/lib/aarch64-linux-gnu)
    find_path(PCAP_INCLUDE_DIR NAMES pcap.h)

    if(PCAP_LIBRARY AND PCAP_INCLUDE_DIR)
        message(STATUS "Found libpcap via manual search.")
        set(PCAP_FOUND TRUE)
        set(PCAP_LIBRARIES ${PCAP_LIBRARY})
        set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
    else()
        message(FATAL_ERROR "libpcap not found. Please check your installation.")
    endif()
endif()

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

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/rs_fec/include
    ${CMAKE_SOURCE_DIR}/lib/ESP32_WiFi_Injection_Sinffer/include
)

# Add executable
file(GLOB SRC_FILES src/*.cpp)
add_executable(${PROJECT_NAME} ${SRC_FILES})

# Link libraries
list(REMOVE_ITEM OpenCV_LIBS opencv_viz opencv_hdf)
target_link_libraries(${PROJECT_NAME}
    ESP32_WiFi_Injection_Sinffer
    rs_fec
    ${PCAP_LIBRARIES}
    #${SDL2_LIBRARIES}
    Threads::Threads
    ${OpenCV_LIBS}
    #PkgConfig::FFMPEG
)
