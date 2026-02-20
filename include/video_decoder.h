#ifndef VIDEO_DEC_H
#define VIDEO_DEC_H

#include <cstddef>
#include <cstdint>
#include <vector>
#include <atomic>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>

#include "turbojpeg.h"

// Callback for decoded video frames (RGB)
typedef void (*VideoFrameCallback)(const std::vector<uint8_t>& rgb, int width, int height);

// Video decoder using libjpeg-turbo
class VideoDecoder {
public:
    VideoDecoder();
    ~VideoDecoder();

    void push_packet(const uint8_t* data, size_t size, bool vsync, uint8_t count);
    std::vector<uint8_t> get_decoded_frame(); // returns RGB
    int get_width() const { return current_width_; }
    int get_height() const { return current_height_; }

private:
    void decoder_thread();

    tjhandle tj_instance_;
    std::thread decoder_thread_;
    std::atomic<bool> decoding_{false};

    std::queue<std::vector<uint8_t>> packet_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;

    std::vector<uint8_t> current_frame_;
    std::mutex frame_mutex_;
    int current_width_ = 0, current_height_ = 0;
};

// Global callback for packet pool (to be used by VideoDecoder)
void video_callback(const uint8_t* data, size_t size, bool vsync, uint8_t count);
void video_stop();

#endif