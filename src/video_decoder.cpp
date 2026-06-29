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
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <cmath>  // for M_PI
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
std::mutex decoded_mutex;
std::optional<DecodedFrame> latest_decoded_frame;
std::atomic<bool> running{true};
tjhandle tj_instance_;
ObjectDetector object_detector;

SDL_Renderer* renderer_ = nullptr;
TTF_Font* font_ = nullptr;
SDL_Texture* frame_texture_ = nullptr;
SDL_Texture* output_texture_ = nullptr;
int last_width_ = 0, last_height_ = 0;
int output_width_ = 0, output_height_ = 0;
int screen_width_ = 0, screen_height_ = 0;

std::deque<std::chrono::steady_clock::time_point> frame_timestamps_;
static constexpr int FPS_WINDOW = 30;
static constexpr int SCREEN_REFRESH_MS = 16; // ~60Hz
float current_fps_ = 0.0f;

//===================img resize=========================
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

void update_frame_texture(const std::vector<uint8_t>& frame_rgb, int width, int height) {
    if (frame_rgb.empty() || width <= 0 || height <= 0) return;

    if (!frame_texture_ || width != last_width_ || height != last_height_) {
        if (frame_texture_) SDL_DestroyTexture(frame_texture_);
        frame_texture_ = SDL_CreateTexture(renderer_, SDL_PIXELFORMAT_RGB24, SDL_TEXTUREACCESS_STREAMING, width, height);
        last_width_ = width;
        last_height_ = height;
    }

    void* pixels = nullptr;
    int pitch = 0;
    if (SDL_LockTexture(frame_texture_, nullptr, &pixels, &pitch) == 0) {
        const int src_pitch = width * 3;
        const uint8_t* src = frame_rgb.data();
        uint8_t* dst = static_cast<uint8_t*>(pixels);
        for (int y = 0; y < height; ++y) {
            std::memcpy(dst + y * pitch, src + y * src_pitch, src_pitch);
        }
        SDL_UnlockTexture(frame_texture_);
    }
}

void update_fps(std::chrono::steady_clock::time_point frame_timestamp) {
    frame_timestamps_.push_back(frame_timestamp);
    if (frame_timestamps_.size() > FPS_WINDOW) frame_timestamps_.pop_front();

    if (frame_timestamps_.size() >= 2) {
        auto span = std::chrono::duration_cast<std::chrono::milliseconds>(frame_timestamps_.back() - frame_timestamps_.front());
        if (span.count() > 0) {
            current_fps_ = (frame_timestamps_.size() - 1) * 1000.0f / span.count();
        }
    }
}

void render_frame_to_target(int width, int height) {
    if (!renderer_) return;

    const bool side_by_side = hud.getDisplayMode() == DISPLAY_SIDE_BY_SIDE;
    const int viewport_width = side_by_side ? screen_width_ / 2 : screen_width_;
    const int viewport_height = screen_height_;

    if (!output_texture_ || output_width_ != viewport_width || output_height_ != viewport_height) {
        if (output_texture_) SDL_DestroyTexture(output_texture_);
        output_texture_ = SDL_CreateTexture(renderer_, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_TARGET, viewport_width, viewport_height);
        output_width_ = viewport_width;
        output_height_ = viewport_height;
    }
    if (!output_texture_) return;

    SDL_SetRenderTarget(renderer_, output_texture_);
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
    SDL_RenderClear(renderer_);

    if (frame_texture_ && width > 0 && height > 0) {
        const float scale_x = static_cast<float>(viewport_width) / static_cast<float>(width);
        const float scale_y = static_cast<float>(viewport_height) / static_cast<float>(height);
        const float scale = std::min(scale_x, scale_y);
        const int disp_w = static_cast<int>(width * scale);
        const int disp_h = static_cast<int>(height * scale);
        const int disp_x = (viewport_width - disp_w) / 2;
        const int disp_y = (viewport_height - disp_h) / 2;
        SDL_Rect dst_rect = {disp_x, disp_y, disp_w, disp_h};
        SDL_RenderCopy(renderer_, frame_texture_, nullptr, &dst_rect);
    }

    hud.renderOSD(viewport_width, viewport_height);

    SDL_SetRenderTarget(renderer_, nullptr);
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 255);
    SDL_RenderClear(renderer_);
    if (side_by_side) {
        SDL_Rect left_dst = {0, 0, viewport_width, viewport_height};
        SDL_Rect right_dst = {viewport_width, 0, viewport_width, viewport_height};
        SDL_RenderCopy(renderer_, output_texture_, nullptr, &left_dst);
        SDL_RenderCopy(renderer_, output_texture_, nullptr, &right_dst);
    } else {
        SDL_RenderCopy(renderer_, output_texture_, nullptr, nullptr);
    }
    
    render_fps(current_fps_);

    hud.draw(screen_width_, screen_height_);

    SDL_RenderPresent(renderer_);
}
//===============================================

void video_callback(const uint8_t* data, size_t size, bool vsync, uint8_t count) {
    std::lock_guard<std::mutex> lock(queue_mutex);

    ImageBuffer pack;
    pack.buffer.assign(data, data + size);
    pack.can_decode = vsync;
    pack.count = count;

    pack_buffer.push_back(pack);

    pack_buffer_cv_.notify_all();
}

void packet_assembler_thread() {
    tjhandle tj = tjInitDecompress();
    if (!tj) {
        std::cerr << "Failed to init libjpeg-turbo in assembler thread" << std::endl;
        return;
    }

    std::vector<uint8_t> img_buffer;
    uint8_t counter = 0;
    uint32_t broken_img = 0;

    while (running) {
        ImageBuffer packet;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            pack_buffer_cv_.wait_for(lock, std::chrono::milliseconds(5), []{
                return !pack_buffer.empty() || !running;
            });
            if (!running && pack_buffer.empty()) break;
            if (pack_buffer.empty()) continue;
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
            if (counter == static_cast<int>(packet.count) + 1) {
                int width = 0, height = 0, subsamp = 0;
                if (tjDecompressHeader2(tj, img_buffer.data(), img_buffer.size(), &width, &height, &subsamp) != 0) {
                    std::cerr << "JPEG header decode failed: " << tjGetErrorStr() << std::endl;
                } else {
                    std::vector<uint8_t> rgb(width * height * 3);
                    if (tjDecompress2(tj, img_buffer.data(), img_buffer.size(), rgb.data(), width, 0, height, TJPF_RGB, TJFLAG_FASTDCT) != 0) {
                        std::cerr << "JPEG decode failed: " << tjGetErrorStr() << std::endl;
                    } else {
                        std::lock_guard<std::mutex> decoded_lock(decoded_mutex);
                        latest_decoded_frame = DecodedFrame{std::move(rgb), width, height, std::chrono::steady_clock::now()};
                    }
                }
            } else {
                broken_img++;
            }
            counter = 0;
            img_buffer.clear();
        }
    }

    tjDestroy(tj);
    std::cout << "Assembler thread: broken img count = " << broken_img << std::endl;
}

void decoder_thread() {
    // Initialize SDL (renderer thread only)
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
    int screen_w = 1280, screen_h = 720;
    SDL_DisplayMode dm;
    if (SDL_GetDesktopDisplayMode(0, &dm) == 0) {
        screen_w = dm.w;
        screen_h = dm.h;
    }
    SDL_Window* window = SDL_CreateWindow("Video Receiver", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, screen_w, screen_h, SDL_WINDOW_FULLSCREEN);
    if (!window) {
        std::cerr << "Window creation failed: " << SDL_GetError() << std::endl;
        TTF_Quit();
        SDL_Quit();
        return;
    }
    renderer_ = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer_) {
        std::cerr << "Renderer creation failed: " << SDL_GetError() << std::endl;
        SDL_DestroyWindow(window);
        TTF_Quit();
        SDL_Quit();
        return;
    }

    // Load font
    TTF_Font* font = TTF_OpenFont("./DejaVuSans.ttf", 18);
    if (!font) font = TTF_OpenFont("/usr/share/fonts/TTF/DejaVuSans.ttf", 18);
    if (!font) {
        std::cerr << "Failed to load font: " << TTF_GetError() << std::endl;
    }

    // Load object detection model (optional)
    if (!object_detector.loadModel("models/yolov4-tiny.weights", "models/yolov4-tiny.cfg")) {
        std::cout << "Object detection model not loaded. Tracking disabled." << std::endl;
    }

    font_ = font;
    hud.init(renderer_, font);
    screen_width_ = screen_w;
    screen_height_ = screen_h;

    // Start packet assembler/decoder thread (runs at own pace)
    std::thread assembler(packet_assembler_thread);

    // Main render loop: runs at fixed refresh_interval (60 Hz)
    auto last_refresh = std::chrono::steady_clock::now();
    const auto refresh_interval = std::chrono::milliseconds(SCREEN_REFRESH_MS);

    while (running) {
        auto now = std::chrono::steady_clock::now();
        if (now - last_refresh >= refresh_interval) {
            last_refresh = now;
            std::optional<DecodedFrame> frame_to_upload;
            {
                std::lock_guard<std::mutex> decoded_lock(decoded_mutex);
                if (latest_decoded_frame) {
                    frame_to_upload = std::move(latest_decoded_frame);
                    latest_decoded_frame.reset();
                }
            }

            if (frame_to_upload) {
                update_frame_texture(frame_to_upload->rgb, frame_to_upload->width, frame_to_upload->height);
                update_fps(frame_to_upload->timestamp);
            }
            render_frame_to_target(last_width_, last_height_);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    if (assembler.joinable()) assembler.join();

    if (font) TTF_CloseFont(font);
    if (output_texture_) {
        SDL_DestroyTexture(output_texture_);
        output_texture_ = nullptr;
    }
    if (frame_texture_) {
        SDL_DestroyTexture(frame_texture_);
        frame_texture_ = nullptr;
    }
    SDL_DestroyRenderer(renderer_);
    renderer_ = nullptr;
    SDL_DestroyWindow(window);
    TTF_Quit();
    SDL_Quit();
}

void video_stop() {
    running = false;
    pack_buffer_cv_.notify_all();
}
