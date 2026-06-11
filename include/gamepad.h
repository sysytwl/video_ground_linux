#ifndef GAMEPAD_H
#define GAMEPAD_H

#include <SDL.h>

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
    uint16_t GamepadState[16] = {0};
};

#endif