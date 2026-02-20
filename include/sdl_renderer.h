#ifndef SDL_RENDERER_H
#define SDL_RENDERER_H

#include <SDL.h>
#include <SDL_ttf.h>
#include <vector>
#include <deque>
#include <chrono>

class SDLRenderer {
public:
    SDLRenderer(SDL_Renderer* renderer, TTF_Font* font, int screen_w, int screen_h);
    ~SDLRenderer();

    void render_frame(const std::vector<uint8_t>& frame_rgb, int width, int height);
    void render_fps(float fps);
    void render_center_cross();
    void setScreenSize(int w, int h) { screen_width_ = w; screen_height_ = h; }

private:
    SDL_Renderer* renderer_;
    TTF_Font* font_;
    SDL_Texture* frame_texture_ = nullptr;
    int last_width_ = 0, last_height_ = 0;
    int screen_width_, screen_height_;

    std::deque<std::chrono::steady_clock::time_point> frame_timestamps_;
    static constexpr int FPS_WINDOW = 6;
};

#endif