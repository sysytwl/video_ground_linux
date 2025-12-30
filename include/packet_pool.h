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
#include "wifi_packet.h"

#define FEC_K 4
#define FEC_N 7

// C-style callback for decoded data
typedef void (*PacketCallback)(const uint8_t* data, size_t size, bool vsync);

class PacketPool {
private:
    struct FECFrame {
        std::vector<std::unique_ptr<uint8_t[]>> block_data;
        std::vector<bool> block_status;
        std::vector<bool> vsync_flags;
        size_t data_size;
        uint32_t frame_index;
        std::atomic<bool> is_decoded;
        std::chrono::steady_clock::time_point creation_time;
        
        FECFrame() : data_size(0), frame_index(0), is_decoded(false) {
            block_data.resize(FEC_N);
            block_status.resize(FEC_N, false);
            vsync_flags.resize(FEC_N, false);
            
            for (int i = 0; i < FEC_N; i++) {
                block_data[i] = std::make_unique<uint8_t[]>(1500);
            }
        }
        
        // Check if we have enough parts for decoding
        bool can_decode() const {
            int count = 0;
            for (int i = 0; i < FEC_N; i++) {
                if (block_status[i]) count++;
            }
            return count >= FEC_K;
        }
        
        // Get available packets count
        int available_packets() const {
            int count = 0;
            for (bool status : block_status) {
                if (status) count++;
            }
            return count;
        }
        
        // Reset frame for reuse
        void reset(uint32_t new_frame_index) {
            frame_index = new_frame_index;
            data_size = 0;
            is_decoded = false;
            std::fill(block_status.begin(), block_status.end(), false);
            std::fill(vsync_flags.begin(), vsync_flags.end(), false);
            creation_time = std::chrono::steady_clock::now();
        }
        
        // Check if frame is stale (older than timeout)
        bool is_stale(std::chrono::milliseconds timeout) const {
            auto now = std::chrono::steady_clock::now();
            return (now - creation_time) > timeout;
        }
    };
    
    struct ReceivedPacket {
        uint32_t frame_index;
        uint8_t part_index;
        std::unique_ptr<uint8_t[]> data;
        size_t data_size;
        bool vsync;
        
        ReceivedPacket(uint32_t frame_idx, uint8_t part_idx, 
                      const uint8_t* src_data, size_t src_size, bool vsync_flag)
            : frame_index(frame_idx), part_index(part_idx), 
              data(std::make_unique<uint8_t[]>(src_size)),
              data_size(src_size), vsync(vsync_flag) {
            memcpy(data.get(), src_data, src_size);
        }
    };

    // Flexible packet buffer
    std::queue<std::shared_ptr<ReceivedPacket>> packet_buffer_;
    size_t max_packet_buffer_size_ = 10000;  // Configurable buffer size
    
    // Single active FEC frame
    std::unique_ptr<FECFrame> active_frame_;
    
    // Thread management
    std::vector<std::thread> decoding_threads_;
    std::atomic<bool> running_;
    
    // Synchronization
    std::mutex pool_mutex_;
    std::condition_variable packet_available_cv_;
    std::condition_variable buffer_space_available_cv_;
    
    // Statistics
    std::atomic<uint64_t> total_packets_;
    std::atomic<uint64_t> packets_recovered_;
    std::atomic<uint64_t> packets_received_;
    std::atomic<uint64_t> packets_wasted_;
    std::atomic<uint64_t> frames_decoded_;
    std::atomic<uint64_t> frames_discarded_;
    
    time_t start_time = 0;

    PacketCallback callback_;
    void* callback_user_data_;
    
    // Timeout for stale frames (milliseconds)
    std::chrono::milliseconds frame_timeout_{1000};
    
    void decoder_thread_func(int id);
    void process_active_frame();
    void flush_stale_frame();
    
public:
    PacketPool(size_t max_buffer_size = 10000);
    ~PacketPool();

    // Add packet to buffer
    bool add_packet(uint32_t frame_index, uint8_t part_index, 
                    const uint8_t* data, size_t data_size, bool vsync);
    
    // Set buffer size (can be called dynamically)
    void set_buffer_size(size_t new_size);

    // Start/stop processing with specified number of decoder threads
    void start_processing(int num_threads = 1, 
                         PacketCallback callback = nullptr,
                         void* user_data = nullptr);
    void stop_processing();

    // Statistics
    void get_statistics(uint64_t& total, uint64_t& received, 
                       uint64_t& recovered, uint64_t& wasted,
                       uint64_t& decoded, uint64_t& discarded) const;
    
    // Set frame timeout
    void set_frame_timeout(std::chrono::milliseconds timeout);
};

#endif // PACKET_POOL_H