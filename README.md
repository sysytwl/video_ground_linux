# WiFi Packet Sniffer

A multi-threaded WiFi packet sniffer with Radiotap header support.

## Features
- Radiotap header parsing
- MAC address filtering
- Multi-threaded packet processing
- Configurable log levels
- Thread-safe packet pool
- MJPEG AVI recording to `~/Videos` (press `R` to start or stop)

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
```

## AppImage

Build a portable x86_64 AppImage with the bundled linuxdeploy and appimagetool binaries:

```bash
chmod +x package-appimage.sh
./package-appimage.sh
```

The output is `WiFiVideoReceiver-x86_64.AppImage`. Packet capture still requires the
host to grant the application sufficient network capabilities or run it with the
required privileges.