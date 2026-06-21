#include <SDL.h>
#include <SDL_ttf.h>
#include <algorithm>
#include <vector>
#include <deque>
#include <chrono>
#include <turbojpeg.h>
#include <iostream>
#include <cstring>
#include <condition_variable>
#include <optional>
#include <thread>
#include <cmath>  // for M_PI
#include <string>
#include "hud_overlay.h"
#include "object_detector.h"
#include "msp.h"
#include "turbojpeg.h"
#include "video_decoder.h"


extern HUDOverlay hud;

struct ImageBuffer {
    std::vector<uint8_t> buffer;
    bool can_decode;
    uint8_t count;
};

struct DecodedFrame {
    std::vector<uint8_t> rgb;
    int width = 0;
    int height = 0;
    std::chrono::steady_clock::time_point timestamp;
};

std::deque<ImageBuffer> pack_buffer;
std::mutex queue_mutex;
std::condition_variable pack_buffer_cv_;

// jpeg buffer and separate decode thread removed — decoding done inline in assembler

std::mutex decoded_mutex;
std::optional<DecodedFrame> latest_decoded_frame;
std::atomic<uint32_t> broken_img{0};
std::atomic<bool> running{true};
tjhandle tj_instance_;
ObjectDetector object_detector;

SDL_Renderer* renderer_;
TTF_Font* font_;
SDL_Texture* frame_texture_ = nullptr;
SDL_Texture* render_target_texture_ = nullptr;
int last_width_ = 0, last_height_ = 0;
int screen_width_, screen_height_;

std::deque<std::chrono::steady_clock::time_point> frame_timestamps_;
static constexpr int FPS_WINDOW = 30;
static constexpr int SCREEN_REFRESH_MS = 16; // ~60Hz

//===================================================================

void render_fps(float fps) {
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

void render_center_cross() {
    int cx = screen_width_ / 2;
    int cy = screen_height_ / 2;
    int len = 15;
    SDL_SetRenderDrawColor(renderer_, 255, 0, 0, 255);
    SDL_RenderDrawLine(renderer_, cx - len, cy, cx + len, cy);
    SDL_RenderDrawLine(renderer_, cx, cy - len, cx, cy + len);
}

void packet_assembler_thread() {
    std::vector<uint8_t> img_buffer;
    uint8_t counter = 0;

    while (running) {
        ImageBuffer packet;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            pack_buffer_cv_.wait(lock, [] { return !pack_buffer.empty() || !running; });
            if (!running && pack_buffer.empty()) break;
            packet = std::move(pack_buffer.front());
            pack_buffer.pop_front();
        }

        if ((packet.count == 0) && (!img_buffer.empty())) {
            img_buffer.clear();
            counter = 0;
            broken_img++;
        }

        img_buffer.insert(img_buffer.end(), packet.buffer.begin(), packet.buffer.end());
        counter++;

        if (packet.can_decode) {
            if (counter == packet.count + 1) {
                // Decode the completed JPEG
                // if (!img_buffer.empty() && tj_instance_) {
                int width = 0, height = 0, subsamp = 0;
                if (tjDecompressHeader2(tj_instance_, img_buffer.data(), img_buffer.size(), &width, &height, &subsamp) == 0) {
                    std::vector<uint8_t> rgb;
                    try {
                        rgb.resize(width * height * 3);
                    } catch (...) {
                        rgb.clear();
                        continue;
                    }

                    // if (!rgb.empty()) {
                    if (tjDecompress2(tj_instance_, img_buffer.data(), img_buffer.size(), rgb.data(), width, 0, height, TJPF_RGB, TJFLAG_FASTDCT) == 0) {
                        std::lock_guard<std::mutex> lock(decoded_mutex);
                        latest_decoded_frame = DecodedFrame{std::move(rgb), width, height, std::chrono::steady_clock::now()};
                    } else {
                        broken_img++;
                    }
                    // }
                } else {
                    broken_img++;
                }
                // } else {
                //     broken_img++;
                // }
            } else {
                broken_img++;
            }

            counter = 0;
            img_buffer.clear();
        }
    }
}



void update_frame_texture(const std::vector<uint8_t>& frame_rgb, int width, int height) {
    if (!frame_texture_ || width != last_width_ || height != last_height_) {
        if (frame_texture_) SDL_DestroyTexture(frame_texture_);
        frame_texture_ = SDL_CreateTexture(renderer_, SDL_PIXELFORMAT_RGB24, SDL_TEXTUREACCESS_STREAMING, width, height);
        last_width_ = width;
        last_height_ = height;
    }

    void* pixels = nullptr;
    int pitch = 0;
    if (SDL_LockTexture(frame_texture_, nullptr, &pixels, &pitch) == 0) {
        memcpy(pixels, frame_rgb.data(), frame_rgb.size());
        SDL_UnlockTexture(frame_texture_);
    }
}

void render_frame_to_target(int width, int height) {
    if (!frame_texture_ || !render_target_texture_) return;

    SDL_SetRenderTarget(renderer_, render_target_texture_);
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
    SDL_RenderClear(renderer_);

    bool side_by_side = hud.getDisplayMode() == DISPLAY_SIDE_BY_SIDE;
    float target_width = side_by_side ? (float)screen_width_ / 2.0f : (float)screen_width_;
    float scale_x = target_width / (float)width;
    float scale_y = (float)screen_height_ / (float)height;
    float scale = std::min(scale_x, scale_y);
    int disp_w = static_cast<int>(width * scale);
    int disp_h = static_cast<int>(height * scale);
    int disp_y = (screen_height_ - disp_h) / 2;

    if (side_by_side) {
        int disp_x_left = (screen_width_ / 2 - disp_w) / 2;
        int disp_x_right = screen_width_ / 2 + disp_x_left;
        SDL_Rect left_dst = {disp_x_left, disp_y, disp_w, disp_h};
        SDL_Rect right_dst = {disp_x_right, disp_y, disp_w, disp_h};
        SDL_RenderCopy(renderer_, frame_texture_, nullptr, &left_dst);
        SDL_RenderCopy(renderer_, frame_texture_, nullptr, &right_dst);
    } else {
        int disp_x = (screen_width_ - disp_w) / 2;
        SDL_Rect dst = {disp_x, disp_y, disp_w, disp_h};
        SDL_RenderCopy(renderer_, frame_texture_, nullptr, &dst);
    }

    hud.render(screen_width_, screen_height_);
    hud.draw(screen_width_, screen_height_);
    SDL_SetRenderTarget(renderer_, nullptr);

    SDL_RenderCopy(renderer_, render_target_texture_, nullptr, nullptr);
}

void video_callback(const uint8_t* data, size_t size, bool vsync, uint8_t count) {
    std::lock_guard<std::mutex> lock(queue_mutex);

    ImageBuffer pack;
    pack.buffer.assign(data, data + size);
    pack.can_decode = vsync;
    pack.count = count;

    pack_buffer.push_back(pack);

    pack_buffer_cv_.notify_all();
}

void decoder_thread() {
    tj_instance_ = tjInitDecompress();
    if (!tj_instance_) throw std::runtime_error("Failed to init libjpeg-turbo");

  // Initialize SDL
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMECONTROLLER) != 0) {
        std::cerr << "SDL init failed: " << SDL_GetError() << std::endl;
        return;
    }
    if (TTF_Init() != 0) {
        std::cerr << "TTF init failed: " << TTF_GetError() << std::endl;
        SDL_Quit();
        return;
    }

    // Create window and renderer
    // Use current desktop resolution for fullscreen when possible
    int screen_w = 1280, screen_h = 720;
    SDL_DisplayMode dm;
    if (SDL_GetDesktopDisplayMode(0, &dm) == 0) {
        screen_w = dm.w;
        screen_h = dm.h;
    }
    screen_width_ = screen_w;
    screen_height_ = screen_h;

    SDL_Window* window = SDL_CreateWindow("Video Receiver",SDL_WINDOWPOS_UNDEFINED,SDL_WINDOWPOS_UNDEFINED,screen_width_, screen_height_,SDL_WINDOW_FULLSCREEN);
    if (!window) {
        std::cerr << "Window creation failed: " << SDL_GetError() << std::endl;
        TTF_Quit();
        SDL_Quit();
        return ;
    }
    renderer_ = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
    if (!renderer_) {
        std::cerr << "Renderer creation failed: " << SDL_GetError() << std::endl;
        SDL_DestroyWindow(window);
        TTF_Quit();
        SDL_Quit();
        return ;
    }

    // Load font
    TTF_Font* font = TTF_OpenFont("./DejaVuSans.ttf", 18);
    if (!font) font = TTF_OpenFont("/usr/share/fonts/TTF/DejaVuSans.ttf", 18);
    if (!font) {
        std::cerr << "Failed to load font: " << TTF_GetError() << std::endl;
        // Continue without font? Fallback to no text.
    }
    font_ = font;

    // Load object detection model (optional)
    if (!object_detector.loadModel("models/yolov4-tiny.weights", "models/yolov4-tiny.cfg")) {
        std::cout << "Object detection model not loaded. Tracking disabled." << std::endl;
    }

    //OSD init
    hud.init(renderer_, font_);

    render_target_texture_ = SDL_CreateTexture(renderer_, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_TARGET, screen_w, screen_h);
    if (!render_target_texture_) {
        std::cerr << "Failed to create render target texture: " << SDL_GetError() << std::endl;
    }

    // img assembler thread (also handles decoding inline)
    std::thread assembler_thread(packet_assembler_thread);

    // main img display 
    auto last_refresh = std::chrono::steady_clock::now();
    const auto refresh_interval = std::chrono::milliseconds(SCREEN_REFRESH_MS);
    while (running) {
        auto now = std::chrono::steady_clock::now();
        if (now - last_refresh < refresh_interval) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        last_refresh = now;

        std::optional<DecodedFrame> frame_to_display;
        {
            std::lock_guard<std::mutex> decoded_lock(decoded_mutex);
            if (latest_decoded_frame) frame_to_display = latest_decoded_frame;
        }

        if (frame_to_display) {
            update_frame_texture(frame_to_display->rgb, frame_to_display->width, frame_to_display->height);
            render_frame_to_target(frame_to_display->width, frame_to_display->height);
        } else {
            if (render_target_texture_) {
                SDL_SetRenderTarget(renderer_, render_target_texture_);
                SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
                SDL_RenderClear(renderer_);
                if (font_) {
                    SDL_Color white = {255,255,255,255};
                    SDL_Surface* surf = TTF_RenderText_Solid(font_, "No Img", white);
                    if (surf) {
                        SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer_, surf);
                        SDL_Rect dst = {screen_w/2 - surf->w/2, screen_h/2 - surf->h/2, surf->w, surf->h};
                        SDL_RenderCopy(renderer_, tex, NULL, &dst);
                        SDL_DestroyTexture(tex);
                        SDL_FreeSurface(surf);
                    }
                }
                hud.render(screen_w, screen_h);
                hud.draw(screen_w, screen_h);
                SDL_SetRenderTarget(renderer_, nullptr);
                SDL_RenderCopy(renderer_, render_target_texture_, nullptr, nullptr);
            }
        }

        SDL_RenderPresent(renderer_);
    }

    running = false;
    pack_buffer_cv_.notify_all();
    if (assembler_thread.joinable()) assembler_thread.join();

    if (font_) TTF_CloseFont(font_);
    if (render_target_texture_) SDL_DestroyTexture(render_target_texture_);
    SDL_DestroyRenderer(renderer_);
    SDL_DestroyWindow(window);
    TTF_Quit();
    SDL_Quit();

    if (tj_instance_) tjDestroy(tj_instance_);

    std::cout << "broken img count:" << broken_img.load() << std::endl;
}

void video_stop() {
    running = false;
    pack_buffer_cv_.notify_all();
    if (frame_texture_) SDL_DestroyTexture(frame_texture_);
}