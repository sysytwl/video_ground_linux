#include "packet_pool.h"
#include <iostream>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <time.h>
#include "fec.h"

#include <stdarg.h>
// Global or static variable
static FILE *log_file = NULL;

// Initialize once
void init_logger() {
    log_file = fopen("log.txt", "a");
}

// Log function
void log_message(const char* format, ...) {
    if (!log_file) return;
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    fflush(log_file);  // Ensure immediate write
    va_end(args);
}

// Cleanup
void close_logger() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}



thread_local ZFE_FEC fec_decoder;
thread_local ZFE_FEC::fec_t* fec_type = nullptr;

PacketPool::PacketPool(size_t max_buffer_size) 
    : max_packet_buffer_size_(max_buffer_size),
      running_(false),
      total_packets_(0),
      packets_recovered_(0),
      packets_received_(0),
      packets_wasted_(0),
      frames_decoded_(0),
      frames_discarded_(0),
      callback_(nullptr),
      callback_user_data_(nullptr),
      active_frame_(std::make_unique<FECFrame>()) {
    start_time = time(NULL);
}

PacketPool::~PacketPool() {
    stop_processing();
}

bool PacketPool::add_packet(uint32_t frame_index, uint8_t part_index, const uint8_t* data, size_t data_size, bool vsync) {
    std::unique_lock<std::mutex> lock(pool_mutex_);
    
    // Wait if buffer is full
    buffer_space_available_cv_.wait(lock, [this]() {
        return packet_buffer_.size() < max_packet_buffer_size_ || !running_;
    });
    
    if (!running_) return false;
    
    // Create packet and add to buffer
    auto packet = std::make_shared<ReceivedPacket>(
        frame_index, part_index, data, data_size, vsync);
    
    packet_buffer_.push(packet);
    packets_received_++;
    
    // Notify decoder thread
    packet_available_cv_.notify_one();
    return true;
}

void PacketPool::set_buffer_size(size_t new_size) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    max_packet_buffer_size_ = new_size;
    buffer_space_available_cv_.notify_all();  // Wake up waiting threads
}

void PacketPool::process_active_frame() {
    if (!active_frame_ || active_frame_->data_size == 0) {
        return;
    }

    // Check if we can decode
    if (active_frame_->can_decode()) {
        // Initialize FEC if needed
        if (fec_type == nullptr) {
            fec_decoder.init_fec();
            fec_type = fec_decoder.fec_new(FEC_K, FEC_N);
        }
        
        // Prepare FEC decoding
        unsigned int* block_indices = new unsigned int[FEC_K];
        uint8_t** in_packets = new uint8_t*[FEC_K];
        uint8_t** out_packets = new uint8_t*[FEC_K];
        
        int fec_pack_counter = FEC_K;

        for (int i = 0; i < FEC_K; i++) {
            if (active_frame_->block_status[i]) {
                in_packets[i] = active_frame_->block_data[i].get();
                block_indices[i] = i;
            } else {
                while(!active_frame_->block_status[fec_pack_counter]){
                    fec_pack_counter++;
                    if(fec_pack_counter>=FEC_N){
                        printf("unknow fec overflow: %d \n", fec_pack_counter);
                        fec_pack_counter=FEC_N-1;
                        break;
                    }
                }
                in_packets[i] = active_frame_->block_data[fec_pack_counter].get();
                block_indices[i] = fec_pack_counter;
                out_packets[i] = active_frame_->block_data[i].get();
                fec_pack_counter++;
                packets_recovered_++;
            }
        }

        fec_decoder.fec_decode(fec_type, in_packets, out_packets, block_indices, active_frame_->data_size);

        //auto during = std::chrono::steady_clock::now() - active_frame_->creation_time;

        // Output all K packets
        for (int i = 0; i < FEC_K; i++) {
            callback_(active_frame_->block_data[i].get(), active_frame_->data_size, active_frame_->vsync_flags[i]);
        }
        
        frames_decoded_++;
        total_packets_ += FEC_K;
        
        // Clean up
        delete[] block_indices;
        delete[] in_packets;
        delete[] out_packets;

    }
    // Check if frame is stale and should be discarded
    else if (active_frame_->is_stale(frame_timeout_)) {
        flush_stale_frame();
    } else {
        printf("incomplete pack, not able to decode. \n");
        flush_stale_frame();
    }
}

void PacketPool::flush_stale_frame() {
    if (!active_frame_) return;
    
    // Output any available packets before discarding
    int available_packets = 0;
    for (int i = 0; i < FEC_K; i++) {
        if (active_frame_->block_status[i]) {
            callback_(active_frame_->block_data[i].get(), active_frame_->data_size, active_frame_->vsync_flags[i]);
            available_packets++;
        }
    }
    
    packets_wasted_ += available_packets;
    frames_discarded_++;
    
    // Reset for next frame
    active_frame_->reset(0);
}

void PacketPool::decoder_thread_func(int id) {
    printf("Decoder thread %d started\n", id);
    
    // Thread-local FEC initialization
    fec_decoder.init_fec();
    fec_type = fec_decoder.fec_new(FEC_K, FEC_N);
    
    while (running_) {
        std::shared_ptr<ReceivedPacket> packet;

        {
            std::unique_lock<std::mutex> lock(pool_mutex_);

            // Wait for packet or shutdown
            packet_available_cv_.wait(lock, [this]() {
                return !running_ || !packet_buffer_.empty();
            });

            if (!running_) break;

            if (packet_buffer_.empty()) {
                continue;
            }

            // Get next packet
            packet = packet_buffer_.front();
            packet_buffer_.pop();

            // Notify that buffer has space
            buffer_space_available_cv_.notify_one();
        }
        
        // Process the packet
        std::lock_guard<std::mutex> lock(pool_mutex_);

        //printf("frame: %d, part: %d \n", packet->frame_index, packet->part_index);
        // Check if this is for the current active frame
        if (active_frame_->frame_index == 0 || 
            active_frame_->frame_index != packet->frame_index) {
            
            // Flush previous frame if it exists
            if (active_frame_->frame_index != 0) {
                process_active_frame();
            }
            
            // Start new frame
            active_frame_->reset(packet->frame_index);
            active_frame_->data_size = packet->data_size;
        }
        
        // Validate packet
        if (packet->part_index >= FEC_N) {
            packets_wasted_++;
            printf("Invalid part index: %d\n", packet->part_index);
            continue;
        }
        
        if (packet->data_size != active_frame_->data_size) {
            packets_wasted_++;
            printf("Size mismatch for frame %u: expected %zu, got %zu\n",
                   packet->frame_index, active_frame_->data_size, packet->data_size);
            continue;
        }
        
        // Store packet in active frame
        std::memcpy(active_frame_->block_data[packet->part_index].get(),
                   packet->data.get(), packet->data_size);
        active_frame_->block_status[packet->part_index] = true;
        active_frame_->vsync_flags[packet->part_index] = packet->vsync;
        
        // Try to decode if we have enough packets
        //process_active_frame();
    }
    
    // Cleanup thread-local FEC
    if (fec_type) {
        fec_decoder.fec_free(&fec_type);
        fec_type = nullptr;
    }
    
    printf("Decoder thread %d stopped\n", id);
}

void PacketPool::start_processing(int num_threads, 
                                 PacketCallback callback, 
                                 void* user_data) {
    if (running_) return;
    
    running_ = true;
    callback_ = callback;
    callback_user_data_ = user_data;
    
    // Start decoder threads
    for (int i = 0; i < num_threads; i++) {
        decoding_threads_.emplace_back(&PacketPool::decoder_thread_func, this, i);
    }
    
    start_time = time(NULL);
    printf("Started packet processing with %d threads\n", num_threads);
}

void PacketPool::stop_processing() {
    if (!running_) return;
    
    running_ = false;
    
    // Wake up all threads
    {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        packet_available_cv_.notify_all();
        buffer_space_available_cv_.notify_all();
    }
    
    // Wait for decoder threads
    for (auto& thread : decoding_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    decoding_threads_.clear();
    
    // Clear buffer
    {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        while (!packet_buffer_.empty()) {
            packet_buffer_.pop();
        }
    }
    
    // Print statistics
    double elapsed_time = difftime(time(NULL), start_time);
    printf("\n=== Packet Pool Statistics ===\n");
    printf("Total frames decoded: %llu\n", (unsigned long long)frames_decoded_.load());
    printf("Total frames discarded: %llu\n", (unsigned long long)frames_discarded_.load());
    printf("Packets received: %llu\n", (unsigned long long)packets_received_.load());
    printf("Packets recovered: %llu\n", (unsigned long long)packets_recovered_.load());
    printf("Packets wasted: %llu\n", (unsigned long long)packets_wasted_.load());
    printf("Processing time: %.2f seconds\n", elapsed_time);
    if (elapsed_time > 0) {
        printf("Data rate: %.2f KB/s\n", 
               (packets_received_ * 1500.0) / (elapsed_time * 1024.0));
    }
    printf("==============================\n");
}

void PacketPool::get_statistics(uint64_t& total, uint64_t& received, 
                               uint64_t& recovered, uint64_t& wasted,
                               uint64_t& decoded, uint64_t& discarded) const {
    total = total_packets_;
    received = packets_received_;
    recovered = packets_recovered_;
    wasted = packets_wasted_;
    decoded = frames_decoded_;
    discarded = frames_discarded_;
}

void PacketPool::set_frame_timeout(std::chrono::milliseconds timeout) {
    frame_timeout_ = timeout;
}