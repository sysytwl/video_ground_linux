# # Create a library for the WiFi sniffer components
# add_library(wifi_sniffer_lib
#     radiotap.cpp
#     wifi_packet.cpp
#     packet_pool.cpp
#     packet_sniffer.cpp
# )

# # Include directories for the library
# target_include_directories(wifi_sniffer_lib
#     PUBLIC
#         ${CMAKE_SOURCE_DIR}/include
#     PRIVATE
#         ${CMAKE_CURRENT_SOURCE_DIR}
# )

# # Link libraries for the library
# target_link_libraries(wifi_sniffer_lib
#     PRIVATE
#         ${PCAP_LIBRARIES}
#         Threads::Threads
# )

# Set compile options for the library
# target_compile_options(wifi_sniffer_lib
#     -Wall
#     -Wextra
#     -Wpedantic
# )

# # Install the library (optional)
# install(TARGETS wifi_sniffer_lib
#     ARCHIVE DESTINATION lib
#     LIBRARY DESTINATION lib
# )