#include <iostream>
#include <thread>
#include <mutex>
#include <queue>
#include <csignal>
#include <atomic>
#include <vector>
#include <algorithm>
#include "packet_sniffer.h"
#include "packet_injector.h"
#include "gamepad_osd.h"
#include "video_decoder.h"

// Global instances
PacketSniffer sniffer;
GamepadHandler gamepad;
OSDMenu g_osd_menu; // 全局实例

// Global signal handler
std::atomic<bool> g_signal_caught(false);

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_signal_caught = true;
        std::cout << "\nSignal caught, stopping..." << std::endl;
        sniffer.stop_capture();
    }
}

// Function to discover available interfaces
std::vector<std::string> discover_interfaces() {
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (device = alldevs; device != nullptr; device = device->next) {
            // Check if interface supports monitor mode
            interfaces.push_back(device->name);
        }
        pcap_freealldevs(alldevs);
    }
    
    return interfaces;
}

// Function to handle OSD updates based on gamepad input
void handle_osd_controls() {
    while (!g_signal_caught) {
        GamepadState state = gamepad.get_state();
        
        // Handle D-pad navigation
        if (state.dpad_up) {
            g_osd_menu.navigate_up();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (state.dpad_down) {
            g_osd_menu.navigate_down();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (state.dpad_left) {
            g_osd_menu.navigate_left();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (state.dpad_right) {
            g_osd_menu.navigate_right();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        
        // Handle A button for selection
        if (state.buttons[0]) { // A button
            g_osd_menu.select_current();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        if (state.buttons[6]) { // display menu
            g_osd_menu.display_menu();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        if (state.buttons[7]) { //start button exit
            signal_handler(SIGTERM);
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

int main(int argc, char* argv[]) {

    // Set up signal handler
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    // Start video decoder thread
    std::thread decoder_thread(video_decoder_loop);
    
    // Discover available interfaces
    std::vector<std::string> interfaces = discover_interfaces();
    if (interfaces.empty()) {
        std::cerr << "No network interfaces found!" << std::endl;
        return 1;
    }
    
    // Initialize OSD with discovered interfaces
    g_osd_menu.set_available_interfaces(interfaces);
    std::vector<std::string> macs={"94:b5:55:26:e2:ff","58:bf:25:1b:07:cb"};
    g_osd_menu.set_discovered_macs(macs);
    // Initialize gamepad
    if (!gamepad.initialize()) {
        std::cout << "Gamepad not found, using keyboard fallback" << std::endl;
        // Fallback to keyboard input would go here
    }
    gamepad.start();
    
    // Start OSD control thread
    std::thread osd_control_thread(handle_osd_controls);
    
    while (!g_osd_menu.should_start_capture() && !g_signal_caught) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    if (!g_signal_caught && g_osd_menu.should_start_capture()) {// Start capture
        std::string interface = g_osd_menu.get_selected_interface();
        std::string mac_filter = g_osd_menu.get_selected_mac();

        std::cout << "Starting capture on " << interface;
        if (!mac_filter.empty()) {
            std::cout << " with MAC filter: " << mac_filter;
        }
        std::cout << std::endl;

        // Start packet sniffer
        uint8_t filter_case = mac_filter.empty() ? 2 : 1;
        if (sniffer.initialize(interface, filter_case, mac_filter)) {
            sniffer.start_capture(0); // 0 = infinite
        }
    }

    signal_handler(SIGTERM);

    gamepad.stop();
    video_stop();
    if (osd_control_thread.joinable()) {
        osd_control_thread.join();
    }
    if (decoder_thread.joinable()) {
        decoder_thread.join();
    }

    return 0;
}