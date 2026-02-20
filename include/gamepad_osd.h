#ifndef GAMEPAD_OSD_H
#define GAMEPAD_OSD_H

#include <SDL.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <memory>
#include "hud_overlay.h"  // for HUDConfig

enum RenderMode {
    RENDER_GRAPHIC = 0,
    RENDER_TEXT = 1
};
RenderMode getRenderMode() const;

struct GamepadState {
    float left_x = 0.0f;
    float left_y = 0.0f;
    float right_x = 0.0f;
    float right_y = 0.0f;
    bool buttons[16] = {false};
    bool dpad_up = false;
    bool dpad_down = false;
    bool dpad_left = false;
    bool dpad_right = false;
    
    // Controller packet structure
    uint8_t packet_version = 0x01;
    uint8_t type = 0x02;
    uint32_t buttons_bitmask = 0;
    int16_t left_stick_x = 0;
    int16_t left_stick_y = 0;
    int16_t right_stick_x = 0;
    int16_t right_stick_y = 0;
};

class GamepadHandler {
public:
    GamepadHandler();
    ~GamepadHandler();

    bool init();
    void update();  // call this in main loop
    uint8_t get_state(uint8_t button) const;
    int get_axis(uint8_t axis) const;

private:
    SDL_GameController* controller_ = nullptr;
    GamepadState state_;
    Uint8 button_previous_[16] = {0};
};

class OSDMenu {
public:
    OSDMenu();

    void set_available_interfaces(const std::vector<std::string>& interfaces);
    void set_discovered_macs(const std::vector<std::string>& macs);

    void navigate_up();
    void navigate_down();
    void navigate_left();
    void navigate_right();
    void select_current();
    void toggle_menu();

    void draw(SDL_Renderer* renderer, int width, int height, TTF_Font* font);

    std::string get_selected_interface() const;
    std::string get_selected_mac() const;
    bool should_start_capture() const;

    HUDConfig getHUDConfig() const;
    void setHUDConfig(const HUDConfig& cfg);

private:
    struct MenuItem {
        std::string name;
        std::vector<std::string> options;
        size_t selected = 0;
        bool editable = true;
        bool is_toggle = false;
    };

    std::vector<MenuItem> menu_items_;
    size_t selected_item_ = 0;
    bool menu_visible_ = true;
    mutable std::mutex menu_mutex_;

    std::vector<std::string> available_interfaces_;
    std::vector<std::string> discovered_macs_;
    HUDConfig hud_config_;

    void populate_menu();
    void handle_toggle(MenuItem& item);
};

#endif