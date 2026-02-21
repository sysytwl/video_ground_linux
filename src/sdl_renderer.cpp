#include "sdl_renderer.h"
#include <SDL.h>
#include <SDL_ttf.h>
#include <algorithm>

SDLRenderer::SDLRenderer(SDL_Renderer* renderer, TTF_Font* font, int screen_w, int screen_h)
    : renderer_(renderer), font_(font), screen_width_(screen_w), screen_height_(screen_h) {}

SDLRenderer::~SDLRenderer() {
    if (frame_texture_) SDL_DestroyTexture(frame_texture_);
}

void SDLRenderer::render_frame(const std::vector<uint8_t>& frame_rgb, int width, int height) {
    if (frame_rgb.empty()) return;

    // Create or recreate texture if size changed
    if (!frame_texture_ || width != last_width_ || height != last_height_) {
        if (frame_texture_) SDL_DestroyTexture(frame_texture_);
        frame_texture_ = SDL_CreateTexture(renderer_,
                                           SDL_PIXELFORMAT_RGB24,
                                           SDL_TEXTUREACCESS_STREAMING,
                                           width, height);
        last_width_ = width;
        last_height_ = height;
    }

    void* pixels;
    int pitch;
    SDL_LockTexture(frame_texture_, nullptr, &pixels, &pitch);
    memcpy(pixels, frame_rgb.data(), frame_rgb.size());                                                                                                                                                                                                                        
    SDL_UnlockTexture(frame_texture_);

    // Clear screen
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
    SDL_RenderClear(renderer_);

    // Calculate aspect-ratio preserving rectangle
    float scale_x = (float)screen_width_ / width;
    float scale_y = (float)screen_height_ / height;
    float scale = std::min(scale_x, scale_y);
    int disp_w = width * scale;
    int disp_h = height * scale;
    int disp_x = (screen_width_ - disp_w) / 2;
    int disp_y = (screen_height_ - disp_h) / 2;
    SDL_Rect dst = {disp_x, disp_y, disp_w, disp_h};
    SDL_RenderCopy(renderer_, frame_texture_, nullptr, &dst);

    // Update FPS counter
    auto now = std::chrono::steady_clock::now();
    frame_timestamps_.push_back(now);
    if (frame_timestamps_.size() > FPS_WINDOW) frame_timestamps_.pop_front();

    float fps = 0;
    if (frame_timestamps_.size() >= 2) {
        auto span = std::chrono::duration_cast<std::chrono::milliseconds>(
            frame_timestamps_.back() - frame_timestamps_.front());
        if (span.count() > 0) fps = (frame_timestamps_.size() - 1) * 1000.0f / span.count();
    }
    render_fps(fps);
    //render_center_cross();
}

#include <string>
void SDLRenderer::render_fps(float fps) {
    if (!font_) return;
    std::string text = "FPS: " + std::to_string((int)fps);
    SDL_Color color = {0, 255, 0, 255};
    SDL_Surface* surf = TTF_RenderText_Solid(font_, text.c_str(), color);
    if (surf) {
        SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer_, surf);
        SDL_Rect dst = {10, 10, surf->w, surf->h};
        SDL_RenderCopy(renderer_, tex, nullptr, &dst);
        SDL_DestroyTexture(tex);
        SDL_FreeSurface(surf);
    }
}

void SDLRenderer::render_center_cross() {
    int cx = screen_width_ / 2;
    int cy = screen_height_ / 2;
    int len = 15;
    SDL_SetRenderDrawColor(renderer_, 255, 0, 0, 255);
    SDL_RenderDrawLine(renderer_, cx - len, cy, cx + len, cy);
    SDL_RenderDrawLine(renderer_, cx, cy - len, cx, cy + len);
}