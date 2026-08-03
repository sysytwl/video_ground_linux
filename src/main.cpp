#include <iostream>
#include <thread>
#include <atomic>
#include <csignal>
#include <vector>
#include <SDL.h>
#include <SDL_ttf.h>
#include "packet_sniffer.h"
#include "gamepad.h"
#include "video_decoder.h"
#include "msp.h"
#include "hud_overlay.h"
#include "app_log.h"

// Global instances
PacketSniffer sniffer;
GamepadHandler gamepad;
HUDOverlay hud;

std::atomic<bool> g_running(true);

void signal_handler(int sig) {
    g_running = false;
    sniffer.stop_multi_capture();
}

int main(int argc, char* argv[]) {
    // Signal handling
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
  
    // Initialize components
    if (!gamepad.init()) {
        std::cout << "No gamepad, using ext." << std::endl;
    }

    // Discover interfaces
    auto interfaces = discover_interfaces();
    hud.set_available_interfaces(interfaces);

        // Start MSP serial reader (hard-coded device unless MSP_DEVICE env set)
        if (!msp_start()) {
            std::cerr << "Warning: msp_start() failed to start serial reader" << std::endl;
        }

    hud.set_discovered_devices({});

    std::thread img_decode_thread(decoder_thread); //main display thread
    bool capture_active = false;

    while (g_running) {
        if (!capture_active && hud.consume_scan_request()) {
            auto scan_interfaces = hud.get_selected_interfaces();
            auto discovered_devices = sniffer.scan_devices(scan_interfaces);
            hud.set_discovered_devices(discovered_devices);
        }

        if (hud.should_start_capture() && !capture_active) {
            auto interfaces = hud.get_selected_interfaces();
            DiscoveredDevice device = hud.get_selected_device();
            uint8_t filter_case = device.mac.empty() ? 2 : 1;
            if (!interfaces.empty() && !device.mac.empty() && sniffer.initialize_multi(interfaces, filter_case, device.mac, device.channel)) {
                capture_active = true;
                sniffer.start_multi_capture(0);
            } else {
                std::cerr << "Select a scanned device before starting capture" << std::endl;
            }
        } else if (!hud.should_start_capture() && capture_active) {
            sniffer.stop_multi_capture();
            capture_active = false;
        }

        if (!g_running) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    // Cleanup
    if (capture_active) {
        sniffer.stop_multi_capture();
    }
    msp_stop();
    video_stop();
    if (img_decode_thread.joinable()) img_decode_thread.join();
    app_log_close();

    return 0;
}