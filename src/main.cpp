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

// Global instances
PacketSniffer sniffer;
GamepadHandler gamepad;
HUDOverlay hud;

std::atomic<bool> g_running(true);

void signal_handler(int sig) {
    g_running = false;
    sniffer.stop_capture();
}

// Function to handle OSD updates based on gamepad input
void handle_osd_controls() {
    while (g_running) {
        SDL_Event e;
        while(SDL_PollEvent(&e)  && g_running){
            if (e.type == SDL_KEYDOWN) {
                switch (e.key.keysym.sym) {
                    case SDLK_ESCAPE:
                        signal_handler(SIGTERM);
                        break;
                    case SDLK_m:
                        hud.toggle_menu();
                        break;
                    case SDLK_UP:
                        hud.navigate_up();
                        break;
                    case SDLK_DOWN:
                        hud.navigate_down();
                        break;
                    case SDLK_LEFT:
                        hud.navigate_left();
                        break;
                    case SDLK_RIGHT:
                        hud.navigate_right();
                        break;
                    default:
                        break;
                }
            }
        }

        gamepad.update();

        // Handle D-pad navigation
        if (gamepad.get_state(11)) {
            hud.navigate_up();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (gamepad.get_state(12)) {
            hud.navigate_down();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (gamepad.get_state(13)) {
            hud.navigate_left();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (gamepad.get_state(14)) {
            hud.navigate_right();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        
        // Handle A button for selection
        // if (gamepad.get_state(0)) { // A button
        //     hud.select_current();
        //     std::this_thread::sleep_for(std::chrono::milliseconds(500));
        // }

        if (gamepad.get_state(4)) { //guide: display menu
            hud.toggle_menu();
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

    // Start OSD control thread
    std::thread osd_control_thread(handle_osd_controls);

    std::thread img_decode_thread(decoder_thread);

    while (g_running) {
        // SDL_Event e;
        // while (SDL_PollEvent(&e) && g_running) {
        //     if (e.type == SDL_QUIT) g_running = false;
        //     else if (e.type == SDL_KEYDOWN) {
        //         if (e.key.keysym.sym == SDLK_ESCAPE) g_running = false;
        //     }
        // }

        // Check if we should start capture
        if (hud.should_start_capture()) {
            std::string iface = hud.get_selected_interface();
            std::string mac_filter = hud.get_selected_mac();
            uint8_t filter_case = mac_filter.empty() ? 2 : 1;
            if (sniffer.initialize(iface, filter_case, mac_filter)) {
                sniffer.start_capture(0);
            }
        }

        if (!g_running) break;
    }

    // Cleanup
    sniffer.stop_capture();
        msp_stop();
    video_stop();
    if (img_decode_thread.joinable()) img_decode_thread.join();
    if (osd_control_thread.joinable()) osd_control_thread.join();

    return 0;
}