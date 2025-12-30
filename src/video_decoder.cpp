#include "video_decoder.h"
#include <opencv2/opencv.hpp>
#include <queue>
#include <mutex>
#include <atomic>
#include <vector>
#include <algorithm>
#include <iostream>
#include <thread>
#include <stddef.h>
#include <cstring>

std::queue<std::vector<uint8_t>> pack_buffer;
std::mutex queue_mutex;
std::atomic<bool> running{true};

struct ImageBuffer {
    std::vector<uint8_t> buffer;
    bool can_decode;
};
std::queue<ImageBuffer> img_buffers;


// Simple callback - just store data
void video_callback(const uint8_t* data, size_t size, bool vsync) {
    std::lock_guard<std::mutex> lock(queue_mutex);
    pack_buffer.push(std::vector<uint8_t>(data, data + size));
}

// Helper function to find marker in data
static size_t find_marker(const std::vector<uint8_t>& data, uint8_t marker1, uint8_t marker2) {
    for (size_t i = 0; i + 1 < data.size(); i++) {
        if (data[i] == marker1 && data[i+1] == marker2) {
            return i;
        }
    }
    return std::string::npos;
}


// Try to decode complete images
void img_decode(){
    try {
        while (!img_buffers.empty() && img_buffers.front().can_decode) {
            const auto& buffer = img_buffers.front().buffer;
            
            // Check if buffer is not empty
            if (buffer.empty()) {
                printf("Warning: Empty buffer skipped\n");
                img_buffers.pop();
                break;
            }
            
            cv::Mat img = cv::imdecode(buffer, cv::IMREAD_COLOR);
            if (!img.empty()) {
                cv::namedWindow("Live Video", cv::WINDOW_NORMAL);
                cv::imshow("Live Video", img);
                printf("Decoded image: %dx%d\n", img.cols, img.rows);
            } else {
                printf("Warning: imdecode returned empty image\n");
                // Optional: Save buffer to file for debugging
                // FILE* f = fopen("debug.jpg", "wb");
                // fwrite(buffer.data(), 1, buffer.size(), f);
                // fclose(f);
            }
            img_buffers.pop(); // Remove decoded buffer
        }
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

// Main decoder loop
void video_decoder_loop() {

    std::vector<uint8_t> chunk;
    while (running) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (!pack_buffer.empty()) {
                chunk = std::move(pack_buffer.front());
                pack_buffer.pop();
            }
        } break; //seg error follow

        if (chunk.empty()) {
            // No data available, small sleep to prevent busy waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        // Look for start marker (0xFFD8)
        size_t start_pos = find_marker(chunk, 0xFF, 0xD8);
        if (start_pos != std::string::npos) {
            // Found start marker - create new image buffer
            printf("Found start marker at position %zu\n", start_pos);
                
            // If we have a previous buffer that hasn't been completed, mark it for decoding
            // (though it might be incomplete)
            if (!img_buffers.empty() && !img_buffers.back().can_decode) {
                img_buffers.back().can_decode = true;
                img_decode();
            }

            ImageBuffer new_buffer;
            new_buffer.can_decode = false;
            // Add data from start marker to end of chunk
            new_buffer.buffer.insert(new_buffer.buffer.end(), 
                                        chunk.begin() + start_pos, 
                                        chunk.end());
            img_buffers.push(new_buffer);
        } else {
            img_buffers.back().buffer.insert(img_buffers.back().buffer.end(),
                                                chunk.begin(),
                                                chunk.end());
        }

        chunk.clear();

        // Handle ESC key
        if (cv::waitKey(1) == 27) {
            running = false;
        }
    }
}

void video_stop() {
    running = false;
}