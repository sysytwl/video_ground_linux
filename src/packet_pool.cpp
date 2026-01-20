#include "packet_pool.h"
#include "wifi_inj_sin.h"
#include "radiotap.h"
#include "fec.h"
#include "global_v.h"

#include <iostream>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <time.h>
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

uint32_t calculate_fcs(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    
    return ~crc;
}

int verify_fcs(const uint8_t *frame, size_t total_len) {
    if (total_len < 4) return 0;  // Frame too short for FCS
    
    size_t data_len = total_len - 4;
    uint32_t expected_fcs = calculate_fcs(frame, data_len);
    
    // Extract received FCS (little-endian)
    uint32_t received_fcs = (frame[data_len + 3] << 24) |
                           (frame[data_len + 2] << 16) |
                           (frame[data_len + 1] << 8) |
                           frame[data_len];
    
    return expected_fcs == received_fcs;
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

bool PacketPool::add_packet(const uint8_t* data, size_t data_size) {
    std::unique_lock<std::mutex> lock(pool_mutex_);
    // return if buffer is full
    if (packet_buffer_.size() > max_packet_buffer_size_ || !running_) return  false;

    packet_buffer_.push(std::vector<uint8_t>(data, data+data_size));
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
        log_message("    true \n");
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
       log_message("    timeout\n");
        flush_stale_frame();
    } else {
        log_message("    false \n");
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
    std::vector<uint8_t>  packet;

    while (running_) {
        clock_t start = clock();
        {
            std::unique_lock<std::mutex> lock(pool_mutex_);

            // Wait for packet or shutdown
            packet_available_cv_.wait(lock,[this]() {
                return !running_ || !packet_buffer_.empty();
            });

            if (!running_) break;

            // Fast move operation - O(1)
            packet = std::move(packet_buffer_.front());
            packet_buffer_.pop();
        } 
        if (!running_) break;

        ieee80211_radiotap_iterator radiotap_header;
        ieee80211_radiotap_iterator_init(&radiotap_header, (ieee80211_radiotap_header *)packet.data(), packet.size());

        bool FCS = 0;
        while(ieee80211_radiotap_iterator_next(&radiotap_header) == 0){
            switch (radiotap_header.this_arg_index) {
            case IEEE80211_RADIOTAP_FLAGS:
                if (radiotap_header.this_arg[0] & IEEE80211_RADIOTAP_F_FCS)
                    FCS = 1;
                break;

            case IEEE80211_RADIOTAP_RATE:
                data_rate = radiotap_header.this_arg[0]/2;
                break;

            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                dbm_antsignal = radiotap_header.this_arg[0];
                break;

            default:
                break;
            }
        }

        // if(FCS){
        //     if(!verify_fcs(packet.data() + radiotap_header.max_length, packet.size() - radiotap_header.max_length)){
        //         log_message("FCS check fail!\n");
        //         continue;
        //     }
        // }

        // // Check if we should filter by MAC
        // if (filter_by_mac_ && !target_mac_.empty()) {
        //     if (!WiFiPacket::mac_matches(info.src_mac, target_mac_)) {
        //         return;  // Skip packets not from target MAC
        //     }
        // }

        IEEE80211_MacHeader *IEEE_HEADER = (IEEE80211_MacHeader*)(packet.data() + radiotap_header.max_length);

        // Log packet info if in debug mode
        // std::cout << "WiFi Packet - ";
        // std::cout << WiFiPacket::get_frame_type_string(info.frame_type, info.frame_subtype);
        // std::cout << " Src: " << info.src_mac;
        // std::cout << " Dst: " << info.dst_mac;
        // std::cout << " BSSID: " << info.bssid_mac;
        //std::cout << " Size: " << pkthdr->len<< " bytes";
        // std::cout << " Signal: " << info.radiotapinfo.signal_dbm << "dbm";
        // std::cout << " Noise: " << info.radiotapinfo.noise_dbm << "dbm";
        // std::cout << " Channel: " << info.radiotapinfo.channel_freq << "Hz";
        // std::cout << " DataRate: " << info.radiotapinfo.data_rate << "Mbps" << std::endl;        

        if (IEEE_HEADER->fc.type != 0b10){ //not data type
            std::cout << "wrong frame type, plz set the filter!" << std::endl;
            continue;
        }

        Air2Ground_Header* header = (Air2Ground_Header*)((uint8_t*)IEEE_HEADER + WLAN_IEEE80211_HEADER_SIZE);
        if(header->packet_version != PACKET_VERSION) {
            std::cout << "Wrong pack Version" << std::endl;
            return;
        }

        if (header->type == Air2Ground_Header::Type::Video) {
            Air2Ground_Video_Packet* video_header = (Air2Ground_Video_Packet*)header;
            
            uint32_t frame_index = video_header->frame_index;
            uint8_t part_index = video_header->part_index;
            size_t data_size = packet.size() - radiotap_header.max_length - WLAN_IEEE80211_HEADER_SIZE - Air2Ground_Video_Packet_Header_Size - (FCS ? 4 : 0);

            // Check if this is for the current active frame
            if (active_frame_.frame_index == 0 || active_frame_.frame_index != frame_index) {

                //process last frame
                if (active_frame_.frame_index != 0) {
                    process_active_frame();
                }

                // Start new frame
                log_message("frame: %d  ", frame_index);
                active_frame_.reset(frame_index);
                active_frame_.data_size = data_size;
            }

            // Validate packet
            if (part_index >= FEC_N) {
                packets_wasted_++;
                printf("Invalid part index: %d\n", part_index);
                continue;
            }

            if (data_size != active_frame_.data_size) {
                packets_wasted_++;
                printf("Size mismatch for frame %u: expected %zu, got %zu\n",
                    frame_index, active_frame_.data_size, data_size);
                continue;
            }

            // Store packet in active frame
            memcpy(
                active_frame_.block_data[part_index],
                (uint8_t*) video_header + Air2Ground_Video_Packet_Header_Size,
                data_size
            );
            active_frame_.block_status[part_index] = true;

            log_message(" part: %d    ", part_index);
        }

        packet.clear();

    clock_t end = clock();
    //log_message("Callback took: %ld us  \n ", (end-start)*1000000/CLOCKS_PER_SEC);
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
               (packets_received_ * 1024.0) / (elapsed_time * 1024.0));
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