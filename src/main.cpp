#include <iostream>
#include <thread>
#include <atomic>
#include <csignal>
#include <vector>
#include <SDL.h>
#include <SDL_ttf.h>
#include "packet_sniffer.h"
#include "gamepad_osd.h"
#include "video_decoder.h"

// Global instances
PacketSniffer sniffer;
GamepadHandler gamepad;
OSDMenu g_osd_menu;
VideoDecoder video_decoder;

std::atomic<bool> g_running(true);

void signal_handler(int sig) {
    g_running = false;
    sniffer.stop_capture();
}

// Function to discover interfaces (unchanged)
std::vector<std::string> discover_interfaces() {
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            interfaces.push_back(d->name);
        }
        pcap_freealldevs(alldevs);
    }
    return interfaces;
}

// Function to handle OSD updates based on gamepad input
void handle_osd_controls() {
    while (g_running) {
        gamepad.update();

        // Handle D-pad navigation
        if (gamepad.get_state(11)) {
            g_osd_menu.navigate_up();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (gamepad.get_state(12)) {
            g_osd_menu.navigate_down();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (gamepad.get_state(13)) {
            g_osd_menu.navigate_left();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (gamepad.get_state(14)) {
            g_osd_menu.navigate_right();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        
        // Handle A button for selection
        if (gamepad.get_state(0)) { // A button
            g_osd_menu.select_current();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        if (gamepad.get_state(4)) { //guide: display menu
            g_osd_menu.toggle_menu();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        if (gamepad.get_state(6)) { //start: exit
            signal_handler(SIGTERM);
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

int main(int argc, char* argv[]) {
    // Signal handling
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

  
    // Initialize components
    if (!gamepad.init()) {
        std::cout << "No gamepad, using keyboard fallback (not implemented)." << std::endl;
    }

    // Discover interfaces
    auto interfaces = discover_interfaces();
    g_osd_menu.set_available_interfaces(interfaces);
    std::vector<std::string> macs = {"94:b5:55:26:e2:ff", "58:bf:25:1b:07:cb"};
    g_osd_menu.set_discovered_macs(macs);

    // Main loop
    bool capture_started = false;
    //Uint32 last_gamepad_update = SDL_GetTicks();

    // Start OSD control thread
    std::thread osd_control_thread(handle_osd_controls);

    while (g_running) {
        SDL_Event e;
        while (SDL_PollEvent(&e) && g_running) {
            if (e.type == SDL_QUIT) g_running = false;
            else if (e.type == SDL_KEYDOWN) {
                if (e.key.keysym.sym == SDLK_ESCAPE) g_running = false;
            }
        }

        // Update gamepad at ~60 Hz
        //Uint32 now = SDL_GetTicks();
        //gamepad.update();

        // Check if we should start capture
        if (!capture_started && g_osd_menu.should_start_capture()) {
            std::string iface = g_osd_menu.get_selected_interface();
            std::string mac_filter = g_osd_menu.get_selected_mac();
            uint8_t filter_case = mac_filter.empty() ? 2 : 1;
            if (sniffer.initialize(iface, filter_case, mac_filter)) {
                sniffer.start_capture(0);
                capture_started = true;
            }
        }
    }

    // Cleanup
    sniffer.stop_capture();
    video_stop();
    if (osd_control_thread.joinable()) {
        osd_control_thread.join();
    }

    return 0;
}