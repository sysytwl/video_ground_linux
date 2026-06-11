#include <SDL.h>
#include <SDL_ttf.h>
#include <algorithm>
#include <vector>
#include <deque>
#include <chrono>
#include <turbojpeg.h>
#include <iostream>
#include <cstring>
#include <queue>
#include <condition_variable>
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
std::queue<ImageBuffer> pack_buffer;
std::mutex queue_mutex;
std::condition_variable pack_buffer_cv_;
std::atomic<bool> running{true};
tjhandle tj_instance_;
ObjectDetector object_detector;

SDL_Renderer* renderer_;
TTF_Font* font_;
SDL_Texture* frame_texture_ = nullptr;
int last_width_ = 0, last_height_ = 0;
int screen_width_, screen_height_;

std::deque<std::chrono::steady_clock::time_point> frame_timestamps_;
static constexpr int FPS_WINDOW = 30;

//===================img resize=========================
#include <string>
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

void render_frame(const std::vector<uint8_t>& frame_rgb, int width, int height) {
    if (frame_rgb.empty()) return;

    // Create or recreate texture if size changed
    if (!frame_texture_ || width != last_width_ || height != last_height_) {
        if (frame_texture_) SDL_DestroyTexture(frame_texture_);
        frame_texture_ = SDL_CreateTexture(renderer_,SDL_PIXELFORMAT_RGB24,SDL_TEXTUREACCESS_STREAMING,width, height);
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
//===============================================

void video_callback(const uint8_t* data, size_t size, bool vsync, uint8_t count) {
    std::lock_guard<std::mutex> lock(queue_mutex);

    ImageBuffer pack;
    pack.buffer.assign(data, data + size);
    pack.can_decode = vsync;
    pack.count = count;

    pack_buffer.push(pack);

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
    const int screen_w = 1280, screen_h = 720;
    SDL_Window* window = SDL_CreateWindow("Video Receiver",SDL_WINDOWPOS_UNDEFINED,SDL_WINDOWPOS_UNDEFINED,screen_w, screen_h,SDL_WINDOW_BORDERLESS);
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

    // Load object detection model (optional)
    if (!object_detector.loadModel("models/yolov4-tiny.weights", "models/yolov4-tiny.cfg")) {
        std::cout << "Object detection model not loaded. Tracking disabled." << std::endl;
    }

    hud.init(renderer_, font);

    ImageBuffer current_packet;  // Buffer for current packet
    uint8_t counter = 0;
    std::vector<uint8_t> img_buffer;
    uint32_t broken_img = 0;
    while (running) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            pack_buffer_cv_.wait_for(lock, std::chrono::milliseconds(200), []{ 
                return !pack_buffer.empty() || !running; 
            });
            
            if (!pack_buffer.empty()) {
                current_packet.buffer = std::move(pack_buffer.front().buffer);
                current_packet.count = pack_buffer.front().count;
                current_packet.can_decode = pack_buffer.front().can_decode;
                pack_buffer.pop();
            }
        }

        if (!current_packet.buffer.empty()) {
            if ((current_packet.count == 0) && (!img_buffer.empty())){//missing vsync broken img
                img_buffer.clear();
                counter = 0;
                broken_img++;
            }

            // Append current packet to image buffer
            img_buffer.insert(img_buffer.end(), current_packet.buffer.begin(), current_packet.buffer.end());
            counter++;

            if (current_packet.can_decode){
                if (counter == (current_packet.count+1)){//able to decode
                    // Decode JPEG using libjpeg-turbo
                    int width, height, subsamp;
                    if (tjDecompressHeader2(tj_instance_, img_buffer.data(), img_buffer.size(), &width, &height, &subsamp) != 0) {
                        std::cerr << "JPEG header decode failed: " << tjGetErrorStr() << std::endl;
                        continue;
                    }

                    std::vector<uint8_t> rgb(width * height * 3);
                    if (tjDecompress2(tj_instance_, img_buffer.data(), img_buffer.size(), rgb.data(), width, 0, height, TJPF_RGB, TJFLAG_FASTDCT) != 0) {
                        std::cerr << "JPEG decode failed: " << tjGetErrorStr() << "plz check cam pclk" << std::endl;
                        continue;
                    }

                    // Get decoded frame
                    // Convert to OpenCV Mat for processing
                    //cv::Mat cv_frame(height, width, CV_8UC3, rgb.data());
                    //auto objects = object_detector.detect(cv_frame);
                    // TODO: draw bounding boxes if enabled

                    // Render frame
                    render_frame(rgb, width, height);
                    hud.render(screen_w, screen_h);
                    hud.draw(screen_w, screen_h);//menu

                    SDL_RenderPresent(renderer_);
                } else {
                    broken_img++;
                    //printf("broken img %d  %d\n", counter, current_packet.count+1);
                }

                counter = 0;
                img_buffer.clear();
            }
            current_packet.buffer.clear();
        } else {
            // Show "Waiting for video"
            if (font) {
                SDL_Color white = {255,255,255,255};
                SDL_Surface* surf = TTF_RenderText_Solid(font, "No Img", white);
                if (surf) {
                    SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer_, surf);
                    SDL_Rect dst = {screen_w/2 - surf->w/2, screen_h/2 - surf->h/2, surf->w, surf->h};
                    SDL_RenderCopy(renderer_, tex, NULL, &dst);
                    SDL_DestroyTexture(tex);
                    SDL_FreeSurface(surf);
                }
            }
            hud.draw(screen_w, screen_h);
            SDL_RenderPresent(renderer_);
        }
    }

    if (font) TTF_CloseFont(font);
    SDL_DestroyRenderer(renderer_);
    SDL_DestroyWindow(window);
    TTF_Quit();
    SDL_Quit();

    if (tj_instance_) tjDestroy(tj_instance_);

    std::cout << "broken img count:" << broken_img << std::endl;
}

void video_stop() {
    running = false;
    pack_buffer_cv_.notify_all();
    if (frame_texture_) SDL_DestroyTexture(frame_texture_);
}