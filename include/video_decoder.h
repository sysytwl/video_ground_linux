#ifndef VIDEO_DEC_H
#define VIDEO_DEC_H

#include <stddef.h>
#include <stdint.h>

// Video decoder using libjpeg-turbo
// class VideoDecoder {
// public:
//     VideoDecoder();
//     ~VideoDecoder();

//     void push_packet(const uint8_t* data, size_t size, bool vsync, uint8_t count);
//     std::vector<uint8_t> get_decoded_frame(); // returns RGB
//     int get_width() const { return current_width_; }
//     int get_height() const { return current_height_; }

// private:
//     void decoder_thread();

//     std::thread decoder_thread_;
//     std::atomic<bool> decoding_{false};

//     std::queue<std::vector<uint8_t>> packet_queue_;
//     std::mutex queue_mutex_;
//     std::condition_variable queue_cv_;

//     std::vector<uint8_t> current_frame_;
//     std::mutex frame_mutex_;
//     int current_width_ = 0, current_height_ = 0;
// };

// Global callback for packet pool (to be used by VideoDecoder)
void video_callback(const uint8_t* data, size_t size, bool vsync, uint8_t count);
void video_stop();
void decoder_thread();

#endif