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

PacketPool::PacketPool() 
    : max_packet_buffer_size_(1000),
      running_(false),
      total_packets_(0),
      packets_recovered_(0),
      packets_received_(0),
      packets_wasted_(0),
      frames_decoded_(0),
      frames_discarded_(0),
      callback_(nullptr),
      callback_user_data_(nullptr) {
    start_time = time(NULL);
}

PacketPool::~PacketPool() {
    stop_processing();
}

bool PacketPool::add_packet(uint32_t frame_index, uint8_t part_index, const uint8_t* data, size_t data_size, bool vsync) {
    std::unique_lock<std::mutex> lock(pool_mutex_);

    // return if buffer is full
    if (packet_buffer_.size() > max_packet_buffer_size_ || !running_)
        return  false;

    // Create packet and add to buffer
    ReceivedPacket packet;
    packet.data.assign(data, data+data_size);
    packet.part_index = part_index;
    packet.frame_index = frame_index;
    packet.data_size = data_size;

    packet_buffer_.push(packet);
    packets_received_++;

    //printf("add pack: %d   ", packet_buffer_.size());

    // Notify decoder thread
    packet_available_cv_.notify_one();
    return true;
}

void PacketPool::set_buffer_size(size_t new_size) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    max_packet_buffer_size_ = new_size;
}

void PacketPool::process_active_frame() {

    // Check if we can decode
    if (active_frame_.can_decode()) {
        //log_message("    true \n");
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
            if (active_frame_.block_status[i]) {
                in_packets[i] = active_frame_.block_data[i];
                block_indices[i] = i;
            } else {
                while(!active_frame_.block_status[fec_pack_counter]){
                    fec_pack_counter++;
                }
                in_packets[i] = active_frame_.block_data[fec_pack_counter];
                block_indices[i] = fec_pack_counter;
                out_packets[i] = active_frame_.block_data[i];
                fec_pack_counter++;
                packets_recovered_++;
            }
        }
        
        fec_decoder.fec_decode(
            fec_type, 
            in_packets, 
            out_packets, 
            block_indices, 
            active_frame_.data_size
        );

        //printf("FEC latency: %d   ", active_frame_.get_elapsed_time());

        // Output all K packets
        for (int i = 0; i < FEC_K; i++) {
            callback_(
                active_frame_.block_data[i], 
                active_frame_.data_size, 
                active_frame_.frame_index == 1 && i==0
            );

            // for (int j=0; j< active_frame_.data_size; j++){
            //     log_message(" %X ", active_frame_.block_data[i][j]);
            // }
            // log_message("\n");
        }

        //printf("viedo callback latency: %d \n", active_frame_.get_elapsed_time());
        
        frames_decoded_++;
        total_packets_ += FEC_K;
        
        // Clean up
        delete[] block_indices;
        delete[] in_packets;
        delete[] out_packets;

    }
    // Check if frame is stale and should be discarded
    else if (active_frame_.is_stale(frame_timeout_)) {
       // log_message("    timeout\n");
        flush_stale_frame();
    } else {
        //log_message("    false \n");
        //printf("incomplete pack, not able to decode. \n");
        flush_stale_frame();
    }
}

void PacketPool::flush_stale_frame() {
    // Output any available packets before discarding
    int available_packets = 0;
    for (int i = 0; i < FEC_K; i++) {
        if (active_frame_.block_status[i]) {
            callback_(
                active_frame_.block_data[i], 
                active_frame_.data_size, 
                active_frame_.frame_index==1 && i==0);
            available_packets++;
        }
    }

    packets_wasted_ += available_packets;
    frames_discarded_++;
}

void PacketPool::decoder_thread_func(int id) {
    printf("Decoder thread %d started\n", id);
    
    // Thread-local FEC initialization
    fec_decoder.init_fec();
    fec_type = fec_decoder.fec_new(FEC_K, FEC_N);
    
    //packet
    ReceivedPacket packet;

    while (running_) {
        {        
            std::unique_lock<std::mutex> lock(pool_mutex_);

            // Wait for packet or shutdown
            packet_available_cv_.wait(lock,[this]() {
                return !running_ || !packet_buffer_.empty();
            });

            if (!running_) break;

            //printf("Pack pool: %d latency %d   ", packet_buffer_.size(), active_frame_.get_elapsed_time());

            // Fast move operation - O(1)
            packet = std::move(packet_buffer_.front());
            packet_buffer_.pop();
        }

        // Check if this is for the current active frame
        if (active_frame_.frame_index == 0 || 
            active_frame_.frame_index != packet.frame_index) {

            //process last frame
            if (active_frame_.frame_index != 0) {
                process_active_frame();
            }

            // Start new frame
            //log_message("frame: %d  ",packet.frame_index);
            active_frame_.reset(packet.frame_index);
            active_frame_.data_size = packet.data_size;
        }

        // Validate packet
        if (packet.part_index >= FEC_N) {
            packets_wasted_++;
            printf("Invalid part index: %d\n", packet.part_index);
            continue;
        }

        if (packet.data_size != active_frame_.data_size) {
            packets_wasted_++;
            printf("Size mismatch for frame %u: expected %zu, got %zu\n",
                   packet.frame_index, active_frame_.data_size, packet.data_size);
            continue;
        }

        // Store packet in active frame
        memcpy(
            active_frame_.block_data[packet.part_index],
            packet.data.data(),
            packet.data_size
        );
        active_frame_.block_status[packet.part_index] = true;

        //log_message(" part: %d    ", packet.part_index);
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
    active_frame_.init(FEC_N);
    
    // Start decoder threads
    for (int i = 0; i < num_threads; i++) {
        decoding_threads_.emplace_back(&PacketPool::decoder_thread_func, this, i);
    }
    
    start_time = time(NULL);

    init_logger();

    printf("Started packet processing with %d threads\n", num_threads);
}

void PacketPool::stop_processing() {
    if (!running_) return;
    
    running_ = false;
    
    // Wake up all threads
    {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        packet_available_cv_.notify_all();
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

        active_frame_.deinit();
    }

    close_logger();

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