#include "gamepad.h"

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

uint8_t GamepadHandler::get_state(uint8_t button) const {
    //state_.left_x = SDL_GameControllerGetAxis(controller_, SDL_CONTROLLER_AXIS_LEFTX) / 32767.0f;
    return SDL_GameControllerGetButton(controller_, SDL_GameControllerButton(button));
}

int GamepadHandler::get_axis(uint8_t axis) const {
    return SDL_GameControllerGetAxis(controller_, SDL_GameControllerAxis(axis));
}
