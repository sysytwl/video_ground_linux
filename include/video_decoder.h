#ifndef VIDEO_DEC_H
#define VIDEO_DEC_H

#include <cstddef>
#include <cstdint>

// Global callback for packet pool (to be used by VideoDecoder)
void video_callback(const uint8_t* data, size_t size, bool vsync, uint8_t count);
void video_stop();
void decoder_thread();

#endif
