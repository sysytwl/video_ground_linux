#include "gamepad.h"

#include <algorithm>

GamepadHandler::GamepadHandler() {}

GamepadHandler::~GamepadHandler() {
    if (controller_) SDL_GameControllerClose(controller_);
}

#include <iostream>
bool GamepadHandler::init() {
    if (SDL_InitSubSystem(SDL_INIT_GAMECONTROLLER) != 0) {
        std::cerr << "SDL GameController init failed: " << SDL_GetError() << std::endl;
        return false;
    }
    for (int i = 0; i < SDL_NumJoysticks(); i++) {
        if (SDL_IsGameController(i)) {
            controller_ = SDL_GameControllerOpen(i);
            if (controller_) {
                std::cout << "Gamepad connected: " << SDL_GameControllerName(controller_) << std::endl;
                return true;
            }
        }
    }
    std::cerr << "No gamepad found." << std::endl;
    return false;
}

void GamepadHandler::update() {
    SDL_GameControllerUpdate();
}

bool GamepadHandler::is_connected() const {
    return controller_ && SDL_GameControllerGetAttached(controller_);
}

std::array<uint16_t, 8> GamepadHandler::read_rc_channels() const {
    std::array<uint16_t, 8> channels = {1500, 1500, 1500, 1000, 1500, 1500, 1500, 1500};
    if (!is_connected()) return channels;

    auto map_centered = [](int value, bool inverted) {
        const int adjusted = inverted ? -value : value;
        return static_cast<uint16_t>(std::clamp(1500 + adjusted * 500 / 32767, 1000, 2000));
    };

    channels[0] = map_centered(get_axis(SDL_CONTROLLER_AXIS_RIGHTX), false); // roll
    channels[1] = map_centered(get_axis(SDL_CONTROLLER_AXIS_RIGHTY), true);  // pitch
    channels[2] = map_centered(get_axis(SDL_CONTROLLER_AXIS_LEFTX), false);  // yaw
    channels[3] = map_centered(get_axis(SDL_CONTROLLER_AXIS_LEFTY), true);   // throttle
    return channels;
}

uint8_t GamepadHandler::get_state(uint8_t button) const {
    if (!is_connected()) return 0;
    return SDL_GameControllerGetButton(controller_, SDL_GameControllerButton(button));
}

int GamepadHandler::get_axis(uint8_t axis) const {
    if (!is_connected()) return 0;
    return SDL_GameControllerGetAxis(controller_, SDL_GameControllerAxis(axis));
}
