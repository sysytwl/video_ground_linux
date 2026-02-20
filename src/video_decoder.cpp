#include "video_decoder.h"
#include <turbojpeg.h>
#include <iostream>
#include <cstring>
#include "hud_overlay.h"
#include "object_detector.h"
#include "sdl_renderer.h"

ObjectDetector object_detector;

struct ImageBuffer {
    std::vector<uint8_t> buffer;
    bool can_decode;
    uint8_t count;
};
std::queue<ImageBuffer> pack_buffer;
std::mutex queue_mutex;
std::condition_variable pack_buffer_cv_;
std::atomic<bool> running{true};

// Global queue for incoming packets (from packet pool)
static std::queue<std::vector<uint8_t>> g_packet_queue;
static std::mutex g_queue_mutex;
static std::condition_variable g_queue_cv;
static std::atomic<bool> g_running{true};

void video_callback(const uint8_t* data, size_t size, bool vsync, uint8_t count) {
    std::lock_guard<std::mutex> lock(queue_mutex);

    ImageBuffer pack;
    pack.buffer.assign(data, data + size);
    pack.can_decode = vsync;
    pack.count = count;

    pack_buffer.push(pack);

    pack_buffer_cv_.notify_all();
}

VideoDecoder::VideoDecoder() {
    tj_instance_ = tjInitDecompress();
    if (!tj_instance_) throw std::runtime_error("Failed to init libjpeg-turbo");
    decoding_ = true;
    decoder_thread_ = std::thread(&VideoDecoder::decoder_thread, this);
}

VideoDecoder::~VideoDecoder() {
    decoding_ = false;
    g_queue_cv.notify_all();
    if (decoder_thread_.joinable()) decoder_thread_.join();
    if (tj_instance_) tjDestroy(tj_instance_);
}

void VideoDecoder::push_packet(const uint8_t* data, size_t size, bool vsync, uint8_t count) {
    std::lock_guard<std::mutex> lock(g_queue_mutex);
    g_packet_queue.push(std::vector<uint8_t>(data, data + size));
    g_queue_cv.notify_one();
}

std::vector<uint8_t> VideoDecoder::get_decoded_frame() {
    std::lock_guard<std::mutex> lock(frame_mutex_);
    return current_frame_;
}

#include "gamepad_osd.h"
extern OSDMenu g_osd_menu;
void VideoDecoder::decoder_thread() {
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
    SDL_Window* window = SDL_CreateWindow("WiFi Video Receiver",
                                          SDL_WINDOWPOS_UNDEFINED,
                                          SDL_WINDOWPOS_UNDEFINED,
                                          screen_w, screen_h,
                                          SDL_WINDOW_BORDERLESS);
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
    while (decoding_) {
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
                        cv::Mat cv_frame(height, width, CV_8UC3, rgb.data());

                        // Object detection (every few frames)
                        static int frame_counter = 0;
                        if (++frame_counter % 5 == 0) {
                            //auto objects = object_detector.detect(cv_frame);
                            // TODO: draw bounding boxes if enabled
                        }

                        // Simulate flight data (replace with real telemetry)
                        static float time = 0;
                        time += 0.016f;
                        float speed = 100 + 20*sin(time*0.5f);
                        float alt = 200 + 30*sin(time*0.3f);
                        float heading = fmod(time*10, 360);
                        float pitch = 5*sin(time*0.8f);
                        float roll = 10*sin(time*0.6f);
                        float pred_speed = speed + 5;
                        float pred_alt = alt + 10;
                        float pred_heading = heading + 2;

                        hud.updateFlightData(speed, alt, heading, pitch, roll,pred_speed, pred_alt, pred_heading);
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
                SDL_Surface* surf = TTF_RenderText_Solid(font, "Waiting for video...", white);
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
}

void video_stop() {
    g_running = false;
    g_queue_cv.notify_all();
}