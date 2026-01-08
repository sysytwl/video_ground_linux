# WiFi Packet Sniffer

A multi-threaded WiFi packet sniffer with Radiotap header support.

## Features
- Radiotap header parsing
- MAC address filtering
- Multi-threaded packet processing
- Configurable log levels
- Thread-safe packet pool

## Building

### Requirements
- CMake 3.14+
- C++11 compatible compiler
- libpcap development libraries
- Root privileges for packet capture

### Build Steps
```bash
# Clone and build
mkdir build && cd build
cmake ..
make

# Or with verbose output
cmake -DCMAKE_BUILD_TYPE=Debug ..
make VERBOSE=1