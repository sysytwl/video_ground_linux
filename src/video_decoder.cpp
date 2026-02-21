#include "video_decoder.h"
#include <turbojpeg.h>
#include <iostream>
#include <cstring>
#include <queue>
#include <condition_variable>
#include "hud_overlay.h"
#include "object_detector.h"
#include "sdl_renderer.h"
#include "msp.h"
#include <cmath>  // for M_PI
#include "turbojpeg.h"
#include "gamepad_osd.h"
extern OSDMenu g_osd_menu;

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
    SDL_Renderer* renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
    if (!renderer) {
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

    // Create helper objects
    SDLRenderer sdl_renderer(renderer, font, screen_w, screen_h);
    HUDOverlay hud(renderer, font);

    ImageBuffer current_packet;  // Buffer for current packet
    uint8_t counter = 0;
    std::vector<uint8_t> img_buffer;
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
                printf("missing vsync \n");
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
                        std::cerr << "JPEG decode failed: " << tjGetErrorStr() << std::endl;
                        //continue;
                    }

                    // Get decoded frame
                    // Convert to OpenCV Mat for processing
                    //cv::Mat cv_frame(height, width, CV_8UC3, rgb.data());
                    //auto objects = object_detector.detect(cv_frame);
                    // TODO: draw bounding boxes if enabled

                    int render_mode = g_osd_menu.getRenderMode();
                    hud.setRenderMode(render_mode);

                    if (render_mode == 0) {  // Graphic HUD
                        std::lock_guard<std::mutex> lock(g_osd_mutex);
                        // 单位转换：MSP数据 → 显示单位
                        float speed = g_osd.gps_speed * 0.036f;          // cm/s -> km/h
                        float alt = g_osd.altitude / 100.0f;             // cm -> m
                        float heading = g_osd.yaw * 0.01f;                // 0.01° -> °
                        float pitch_deg = g_osd.pitch * 0.01f;
                        float roll_deg = g_osd.roll * 0.01f;
                        float pitch_rad = pitch_deg * M_PI / 180.0f;      // ° -> rad
                        float roll_rad = roll_deg * M_PI / 180.0f;

                        // 预测值（示例，可从其他来源获取）
                        float pred_speed = speed + 5;
                        float pred_alt = alt + 10;
                        float pred_heading = heading + 2;

                        hud.updateFlightData(speed, alt, heading, pitch_rad, roll_rad,
                                            pred_speed, pred_alt, pred_heading);
                    } else {  // Text OSD
                        std::vector<std::string> lines;
                        int rows = g_osd_screen.rows();
                        for (int r = 0; r < rows; ++r) {
                            std::string row_text = g_osd_screen.getRow(r);
                            // 如果整行都是空格，可以跳过，但保留空行也可以
                            lines.push_back(row_text);
                        }
                        hud.setTextLines(lines);
                        hud.renderOSD(g_osd_screen, screen_w, screen_h);
                    }

                        hud.setConfig(g_osd_menu.getHUDConfig());

                        // Render frame
                        sdl_renderer.render_frame(rgb, width, height);
                        hud.render(screen_w, screen_h);
                        g_osd_menu.draw(renderer, width, height, font);
                        SDL_RenderPresent(renderer);
                } else {
                  printf("broken img %d  %d\n", counter, current_packet.count+1);
                }

                counter = 0;
                img_buffer.clear();
            }
            current_packet.buffer.clear();
        } else {
            // Show "Waiting for video"
            if (font) {
                SDL_Color white = {255,255,255,255};
                SDL_Surface* surf = TTF_RenderText_Solid(font, "No IMG", white);
                if (surf) {
                    SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer, surf);
                    SDL_Rect dst = {screen_w/2 - surf->w/2, screen_h/2 - surf->h/2, surf->w, surf->h};
                    SDL_RenderCopy(renderer, tex, NULL, &dst);
                    SDL_DestroyTexture(tex);
                    SDL_FreeSurface(surf);
                }
            }
            g_osd_menu.draw(renderer, screen_w, screen_h, font);
            SDL_RenderPresent(renderer);
        }
    }

    if (font) TTF_CloseFont(font);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    TTF_Quit();
    SDL_Quit();

    if (tj_instance_) tjDestroy(tj_instance_);
}

void video_stop() {
    running = false;
    pack_buffer_cv_.notify_all();
}