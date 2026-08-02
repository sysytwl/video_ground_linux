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
    sniffer.stop_capture();
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

    std::vector<std::string> macs = {"94:b5:55:26:e2:ff", "58:bf:25:1b:07:cb"};
    hud.set_discovered_macs(macs);

    std::thread img_decode_thread(decoder_thread);
    std::thread capture_thread;
    bool capture_active = false;

    while (g_running) {
        if (hud.should_start_capture() && !capture_active) {
            std::string iface = hud.get_selected_interface();
            std::string mac_filter = hud.get_selected_mac();
            uint8_t filter_case = mac_filter.empty() ? 2 : 1;
            if (sniffer.initialize(iface, filter_case, mac_filter)) {
                capture_active = true;
                capture_thread = std::thread([]() {
                    sniffer.start_capture(0);
                });
            } else {
                std::cerr << "Failed to initialize capture interface: " << iface << std::endl;
            }
        } else if (!hud.should_start_capture() && capture_active) {
            sniffer.stop_capture();
            if (capture_thread.joinable()) capture_thread.join();
            capture_active = false;
        }

        if (!g_running) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    // Cleanup
    if (capture_active) {
        sniffer.stop_capture();
        if (capture_thread.joinable()) capture_thread.join();
    }
    msp_stop();
    video_stop();
    if (img_decode_thread.joinable()) img_decode_thread.join();
    app_log_close();

    return 0;
}