#include "video_decoder.h"
#include <opencv2/opencv.hpp>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <algorithm>
#include <iostream>
#include <thread>
#include <stddef.h>
#include <cstring>

struct ImageBuffer {
    std::vector<uint8_t> buffer;
    bool can_decode;
    uint8_t count;
};
std::queue<ImageBuffer> pack_buffer;
std::mutex queue_mutex;
std::condition_variable pack_buffer_cv_;
std::atomic<bool> running{true};
std::vector<uint8_t> img_buffer;


// Simple callback - just store data
void video_callback(const uint8_t* data, size_t size, bool vsync, uint8_t count) {
    std::lock_guard<std::mutex> lock(queue_mutex);

    ImageBuffer pack;
    pack.buffer.assign(data, data + size);
    pack.can_decode = vsync;
    pack.count = count;

    pack_buffer.push(pack);

    pack_buffer_cv_.notify_all();
}


#include <opencv2/opencv.hpp>
#include <chrono>
#include <deque>

const int MAX_FPS = 5;
std::deque<std::chrono::steady_clock::time_point> timestamps;
bool window_initialized = false;

#include "gamepad_osd.h"

extern OSDMenu g_osd_menu; 


cv::Mat img;
std::chrono::milliseconds duration = (std::chrono::milliseconds)0;
void img_decode(bool img_decode) {
    auto decode_start = std::chrono::steady_clock::now();

    if (img_decode){
        if (img_buffer.empty()) return;
        img = cv::imdecode(img_buffer, cv::IMREAD_COLOR);
        if (img.empty()) return;
    }

    if (!window_initialized) {
        cv::namedWindow("Live", cv::WINDOW_AUTOSIZE);
        cv::setWindowProperty("Live", cv::WND_PROP_FULLSCREEN, cv::WINDOW_FULLSCREEN);
        cv::setWindowProperty("Live", cv::WND_PROP_VSYNC, 0);
        window_initialized = true;
    }
    
    // Fast resize with aspect ratio
    // Try to get actual screen resolution
    // cv::Rect window_rect = cv::getWindowImageRect("Live Video");
    // screen_width = window_rect.width;
    // screen_height = window_rect.height;

    int sw = 1280, sh = 800;
    cv::Mat display = cv::Mat::zeros(sh, sw, CV_8UC3);

    if (img_decode){
        float scale = std::min((float)sw / img.cols, (float)sh / img.rows);
        int nw = img.cols * scale, nh = img.rows * scale;
        int xo = (sw - nw) / 2, yo = (sh - nh) / 2;
        cv::resize(img, display(cv::Rect(xo, yo, nw, nh)), cv::Size(nw, nh));
    }

    // FPS calculation
    auto now = std::chrono::steady_clock::now();
    timestamps.push_back(now);
    if (timestamps.size() > MAX_FPS) timestamps.pop_front();
    
    float fps = 0;
    if (timestamps.size() >= 2) {
        auto span = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamps.back() - timestamps.front());
        if (span.count() > 0) fps = (timestamps.size() - 1) * 1000.0f / span.count();
    }
    
    // Draw red cross at screen center
    int cx = sw / 2, cy = sh / 2, cs = 15;
    cv::line(display, cv::Point(cx - cs, cy), cv::Point(cx + cs, cy), 
             cv::Scalar(0, 0, 255), 2);
    cv::line(display, cv::Point(cx, cy - cs), cv::Point(cx, cy + cs), 
             cv::Scalar(0, 0, 255), 2);
    
    // Draw FPS (green)
    cv::putText(display, cv::format("FPS: %.1f", fps), 
                cv::Point(10, 30), cv::FONT_HERSHEY_SIMPLEX, 0.7, 
                cv::Scalar(0, 255, 0), 2);
    
    // Draw OSD menu - 添加空指针检查
    if (&g_osd_menu != nullptr) {
        g_osd_menu.draw(display, sw, sh);
    }

    cv::putText(display, cv::format("Delay: %d",duration), 
                cv::Point(180, 30), cv::FONT_HERSHEY_SIMPLEX, 0.7, 
                cv::Scalar(0, 255, 0), 2);

    cv::imshow("Live", display);
    cv::waitKey(1);

    auto decode_end = std::chrono::steady_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(decode_end-decode_start);
}

// Main decoder loop
void video_decoder_loop() {
    setenv("vblank_mode", "0", 1);
    setenv("__GL_SYNC_TO_VBLANK", "0", 1);

    running = true;

    ImageBuffer current_packet;  // Buffer for current packet
    uint8_t counter = 0;
    while (running) {
        {
            // Lock scope - only for queue operations
            std::unique_lock<std::mutex> lock(queue_mutex);
            pack_buffer_cv_.wait_for(lock, std::chrono::milliseconds(200), []{ 
                return !pack_buffer.empty() || !running; 
            });
            
            if(!running) break;

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
                if (counter == (current_packet.count+1)){
                  img_decode(true);
                } else {
                  printf("broken img %d  %d\n", counter, current_packet.count+1);
                }

                counter = 0;
                img_buffer.clear();
            }
            current_packet.buffer.clear();
        } else {
            img_decode(false);
        }
    }
}

void video_stop() {
    running = false;
    pack_buffer_cv_.notify_all();
    cv::destroyAllWindows();
}