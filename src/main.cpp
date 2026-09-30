#include <algorithm>
#include <fstream>
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

LinkConfig load_link_config(const char* path) {
    LinkConfig config;
    std::ifstream input(path);
    std::string line;
    while (std::getline(input, line)) {
        const size_t separator = line.find('=');
        if (separator == std::string::npos) continue;
        const std::string key = line.substr(0, separator);
        const int value = std::atoi(line.substr(separator + 1).c_str());
        if (key == "resolution") config.resolution = static_cast<uint8_t>(std::clamp(value, 0, 13));
        else if (key == "jpeg_quality") config.jpeg_quality = static_cast<uint8_t>(std::clamp(value, 0, 63));
        else if (key == "fec_k") config.fec_k = static_cast<uint8_t>(std::clamp(value, 1, 16));
        else if (key == "fec_n") config.fec_n = static_cast<uint8_t>(std::clamp(value, 1, 32));
        else if (key == "wifi_channel" && value > 0) config.wifi_channel = static_cast<uint8_t>(std::clamp(value, 1, 13));
        else if (key == "nrf_channel") config.nrf_channel = static_cast<uint8_t>(std::clamp(value, 0, 125));
        else if (key == "switch_delay_ms") config.switch_delay_ms = static_cast<uint16_t>(std::clamp(value, 100, 5000));
    }
    if (config.fec_n < config.fec_k) config.fec_n = config.fec_k;
    return config;
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
    const LinkConfig link_config = load_link_config("gs.ini");
    msp_set_link_config(link_config);
    if (!sniffer.set_fec(link_config.fec_k, link_config.fec_n)) {
        std::cerr << "Invalid FEC configuration" << std::endl;
        return 1;
    }

        // Start MSP serial reader (hard-coded device unless MSP_DEVICE env set)
        if (!msp_start()) {
            std::cerr << "Warning: msp_start() failed to start serial reader" << std::endl;
        }

    hud.set_discovered_devices({});

    std::thread img_decode_thread(decoder_thread); //main display thread
    bool capture_active = false;
    bool config_rescan_pending = false;
    std::chrono::steady_clock::time_point config_rescan_time;

    while (g_running) {
        LinkConfig requested_config;
        if (hud.consume_config_request(requested_config)) {
            if (capture_active) {
                std::cerr << "Stop capture before applying FEC or channel settings" << std::endl;
            } else {
                if (requested_config.wifi_channel == 0) requested_config.wifi_channel = sniffer.recommended_wifi_channel();
                if (requested_config.nrf_channel == 255) requested_config.nrf_channel = sniffer.recommended_nrf_channel();
                if (sniffer.set_fec(requested_config.fec_k, requested_config.fec_n)) {
                    msp_set_link_config(requested_config);
                    std::cout << "Applying WiFi channel " << static_cast<int>(requested_config.wifi_channel)
                              << " and nRF channel " << static_cast<int>(requested_config.nrf_channel) << std::endl;
                    config_rescan_time = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(requested_config.switch_delay_ms + 700);
                    config_rescan_pending = true;
                }
            }
        }
        if (!capture_active && config_rescan_pending && std::chrono::steady_clock::now() >= config_rescan_time) {
            config_rescan_pending = false;
            auto discovered_devices = sniffer.scan_devices(hud.get_selected_interfaces());
            hud.set_discovered_devices(discovered_devices);
        }
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