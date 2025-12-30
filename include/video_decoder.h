#ifndef VIDEO_DEC_H
#define VIDEO_DEC_H

#include <cstddef>
#include <cstdint>



void video_callback(const uint8_t* data, size_t size, bool vsync);
void video_decoder_loop();
void video_stop();

#endif