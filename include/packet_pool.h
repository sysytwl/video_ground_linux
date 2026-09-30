#ifndef PACKET_POOL_H
#define PACKET_POOL_H
#include <cstring>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <functional>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include "wifi_packet.h"

typedef void (*PacketCallback)(const uint8_t* data, size_t size, bool vsync, uint8_t count);

class PacketPool {
private:
    struct FECFrame {
        uint8_t **block_data;
        bool *block_status;
        size_t data_size;
        uint32_t frame_index=0;
        std::chrono::steady_clock::time_point creation_time;
        uint8_t n_;
        uint8_t k_;

        // Check if we have enough parts for decoding
        bool can_decode() const {
            int count = 0;
            for (int i = 0; i < n_; i++) {
                if (block_status[i]) count++;
            }
            return count >= k_;
        }
        
        // Reset frame for reuse
        void reset(uint32_t new_frame_index) {
            frame_index = new_frame_index;

            for(int i=0; i<n_; i++){
                block_status[i] = false;
            }

            creation_time = std::chrono::steady_clock::now();
        }
        
        // Check if frame is stale (older than timeout)
        bool is_stale(std::chrono::milliseconds timeout) const {
            auto now = std::chrono::steady_clock::now();
            return (now - creation_time) > timeout;
        }

        std::chrono::milliseconds get_elapsed_time() const {
            auto now = std::chrono::steady_clock::now();
            return std::chrono::duration_cast<std::chrono::milliseconds>(now - creation_time);
        }

        void init(int k, int n){
            k_ = k;
            n_ = n;

            block_status = new bool [n];

            block_data = new uint8_t* [n];
            for(int i=0; i<n; i++){
                block_data[i] = new uint8_t [1500];
            }
        }

        void deinit(){
            delete [] block_status;

            for(int i=0; i<n_; i++){
                delete [] block_data[i];
            }
            delete [] block_data;
        }
    };
    FECFrame active_frame_;

    struct ReceivedPacket {
        uint32_t frame_index;
        uint8_t part_index;
        std::vector<uint8_t> data;
        size_t data_size;
    };

    // Flexible packet buffer
    std::queue<std::vector<uint8_t>> packet_buffer_;
    size_t max_packet_buffer_size_ = 1000;  // Configurable buffer size
    

    
    // Thread management
    std::vector<std::thread> decoding_threads_;
    std::atomic<bool> running_;
    
    // Synchronization
    std::mutex pool_mutex_;
    std::condition_variable packet_available_cv_;
    
    // Statistics
    std::atomic<uint64_t> total_packets_;
    std::atomic<uint64_t> packets_recovered_;
    std::atomic<uint64_t> packets_received_;
    std::atomic<uint64_t> duplicate_packets_;
    std::atomic<uint64_t> packets_wasted_;
    std::atomic<uint64_t> frames_decoded_;
    std::atomic<uint64_t> frames_discarded_;
    
    time_t start_time = 0;

    PacketCallback callback_;
    void* callback_user_data_;
    std::unordered_set<uint64_t> seen_parts_;
    
    // Timeout for stale frames (milliseconds)
    std::chrono::milliseconds frame_timeout_{20};
    uint8_t fec_k_ = 4;
    uint8_t fec_n_ = 7;
    
    void decoder_thread_func(int id);
    void process_active_frame();
    void flush_stale_frame();
    
public:
    PacketPool();
    ~PacketPool();

    // Add packet to buffer
    bool add_packet(const uint8_t* data, size_t data_size);
    
    // Set buffer size (can be called dynamically)
    void set_buffer_size(size_t new_size);
    bool set_fec(uint8_t k, uint8_t n);

    // Start/stop processing with specified number of decoder threads
    void start_processing(int num_threads = 1, PacketCallback callback = nullptr);
    void stop_processing();
    
    // Set frame timeout
    void set_frame_timeout(std::chrono::milliseconds timeout);
};

#endif // PACKET_POOL_H