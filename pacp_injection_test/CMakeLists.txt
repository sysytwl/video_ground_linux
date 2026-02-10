cmake_minimum_required(VERSION 3.15)
project(pcap_inject
    VERSION 1.0.0
    DESCRIPTION "PCAP Packet Injection Tool"
    LANGUAGES CXX
)

# Options
option(BUILD_TESTS "Build tests" OFF)
option(BUILD_EXAMPLES "Build examples" ON)
option(ENABLE_DEBUG "Enable debug output" OFF)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Find PCAP
  find_package(PkgConfig)
  pkg_search_module(PC_PCAP libpcap)
  find_path(PCAP_INCLUDE_DIR
    NAMES
      pcap/pcap.h
    HINTS
      ${PC_PCAP_INCLUDE_DIRS}
      ${PCAP_CONFIG_INCLUDE_DIRS}
      "${PCAP_HINTS}/Include"
    PATHS
      "${CMAKE_SOURCE_DIR}/libpcap"
    #VALIDATOR pcap_include_check
  )
 find_library(PCAP_LIBRARIES
    NAMES
      pcap
    HINTS
      ${PC_PCAP_LIBRARY_DIRS}
      ${PCAP_CONFIG_LIBRARY_DIRS}
  )
  set(_pkg_required_vars PCAP_LIBRARY PCAP_INCLUDE_DIR)
  set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
  set(PCAP_LIBRARIES ${PCAP_STATIC_LIBRARIES})
  set(PCAP_LIBRARIES ${PCAP_LIBRARY})
message(STATUS "Found PCAP: ${PCAP_LIBRARIES}")
message(STATUS "PCAP Include: ${PCAP_INCLUDE_DIRS}")

# Include directories
include_directories(
    #${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
)

# Add executable
add_executable(${PROJECT_NAME}
    pcap_inject.cpp
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE ${PCAP_LIBRARIES})

# Add compile definitions based on options
if(ENABLE_DEBUG)
    target_compile_definitions(${PROJECT_NAME} PRIVATE DEBUG=1)
endif()

# Set properties
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
)

# Installation
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Package configuration for distribution
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

# Export targets
export(TARGETS ${PROJECT_NAME}
    FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Targets.cmake"
)
