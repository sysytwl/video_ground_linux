#include "packet_pool.h"
#include "wifi_inj_sin.h"
#include "radiotap.h"
#include "fec.h"
#include "app_log.h"

#include <iostream>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <time.h>
#include <stdarg.h>

uint8_t data_rate;
int8_t dbm_antsignal;

// int verify_fcs(const uint8_t *frame, size_t total_len) {
//     if (total_len < 4) return 0;  // Frame too short for FCS
    
//     size_t data_len = total_len - 4;
//     uint32_t expected_fcs = calculate_fcs(frame, data_len);
    
//     // Extract received FCS (little-endian)
//     uint32_t received_fcs = (frame[data_len + 3] << 24) |
//                            (frame[data_len + 2] << 16) |
//                            (frame[data_len + 1] << 8) |
//                            frame[data_len];
    
//     return expected_fcs == received_fcs;
// }



thread_local ZFE_FEC fec_decoder;
thread_local ZFE_FEC::fec_t* fec_type = nullptr;

PacketPool::PacketPool() 
    : max_packet_buffer_size_(1000),
      running_(false),
      total_packets_(0),
      packets_recovered_(0),
      packets_received_(0),
    duplicate_packets_(0),
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
size_t total_pack_size = 0;
bool PacketPool::add_packet(const uint8_t* data, size_t data_size) {
    std::unique_lock<std::mutex> lock(pool_mutex_);
    // return if buffer is full
    if (packet_buffer_.size() > max_packet_buffer_size_ || !running_) return  false;

    packet_buffer_.push(std::vector<uint8_t>(data, data+data_size));
    packets_received_++;
    total_pack_size += data_size;

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
                active_frame_.block_data[i] + Video_Header, 
                active_frame_.data_size - Video_Header, 
                ((Air2Ground_Video_Packet*)active_frame_.block_data[i])->vsync,
                ((Air2Ground_Video_Packet*)active_frame_.block_data[i])->img_count
            );
        }

        //printf("viedo callback latency: %d \n", active_frame_.get_elapsed_time());
        
        frames_decoded_++;
        total_packets_ += FEC_K;
        seen_parts_.clear();
        
        // Clean up
        delete[] block_indices;
        delete[] in_packets;
        delete[] out_packets;

    }
    // Check if frame is stale and should be discarded
    else if (active_frame_.is_stale(frame_timeout_)) {
       app_log("PACKET_POOL", "   timeout\n");
        flush_stale_frame();
    } else {
        app_log("PACKET_POOL", "incomplete pack, not able to decode. \n");
        flush_stale_frame();
    }
}

void PacketPool::flush_stale_frame() {
    // Output any available packets before discarding
    int available_packets = 0;
    for (int i = 0; i < FEC_K; i++) {
        if (active_frame_.block_status[i]) {
            callback_(
                active_frame_.block_data[i]+ Video_Header,
                active_frame_.data_size - Video_Header, 
                ((Air2Ground_Video_Packet*)active_frame_.block_data[i])->vsync,
                ((Air2Ground_Video_Packet*)active_frame_.block_data[i])->img_count
            );
            available_packets++;
        }
    }

    packets_wasted_ += available_packets;
    frames_discarded_++;
    seen_parts_.clear();
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
        //         app_log("PACKET_POOL", "FCS check fail!\n");
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

        if (IEEE_HEADER->fc.type != 0b10){ //not data type
            std::cout << "wrong frame type, plz set the filter!" << std::endl;
            continue;
        }

        Air2Ground_Header* header = (Air2Ground_Header*)((uint8_t*)IEEE_HEADER + WLAN_IEEE80211_HEADER_SIZE);
        if(header->packet_version != PACKET_VERSION) {
            std::cout << "Wrong pack Version" << std::endl;
            packets_wasted_++;
            continue;
        }

        if (header->type == Air2Ground_Header::Type::Video) {

            uint32_t frame_index = header->frame_index;
            uint8_t part_index = header->part_index;
            size_t data_size = 
                packet.size() 
                - radiotap_header.max_length 
                - WLAN_IEEE80211_HEADER_SIZE 
                - Air2Ground_Header_Size 
                - (FCS ? 4 : 0);

            if (active_frame_.frame_index != 0 && frame_index < active_frame_.frame_index) {
                packets_wasted_++;
                continue;
            }

            // Check if this is for the current active frame
            if (active_frame_.frame_index == 0 || active_frame_.frame_index < frame_index) {

                //process last frame
                if (active_frame_.frame_index != 0) {
                    process_active_frame();
                }

                active_frame_.reset(frame_index);
                active_frame_.data_size = data_size;
                seen_parts_.clear();
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

            uint64_t part_key = (static_cast<uint64_t>(frame_index) << 8) | part_index;
            if (!seen_parts_.insert(part_key).second) {
                duplicate_packets_++;
                continue;
            }

            // Store packet in active frame
            memcpy(
                active_frame_.block_data[part_index],
                (uint8_t*) header + Air2Ground_Header_Size,
                data_size
            );
            active_frame_.block_status[part_index] = true;
        }

        packet.clear();

    clock_t end = clock();
    //app_log("PACKET_POOL", "Callback took: %ld us  \n ", (end-start)*1000000/CLOCKS_PER_SEC);
    }
    
    // Cleanup thread-local FEC
    if (fec_type) {
        fec_decoder.fec_free(&fec_type);
        fec_type = nullptr;
    }
    
    printf("Decoder thread %d stopped\n", id);
}

void PacketPool::start_processing(int num_threads, PacketCallback callback) {
    if (running_) return;

    running_ = true;
    callback_ = callback;
    active_frame_.init(FEC_N);

    decoding_threads_.emplace_back(&PacketPool::decoder_thread_func, this, 0);
    
    start_time = time(NULL);
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
        seen_parts_.clear();
    }

    // Print statistics
    double elapsed_time = difftime(time(NULL), start_time);
    printf("\n=== Packet Pool Statistics ===\n");
    printf("Total pack frames decoded: %llu\n", (unsigned long long)frames_decoded_.load());
    printf("Total pack frames discarded: %llu\n", (unsigned long long)frames_discarded_.load());
    printf("Duplicate packets skipped: %llu\n", (unsigned long long)duplicate_packets_.load());
    printf("Packets recovered: %llu\n", (unsigned long long)packets_recovered_.load());
    printf("Packets wasted: %llu\n", (unsigned long long)packets_wasted_.load());
    printf("Packets received: %llu\n", (unsigned long long)packets_received_.load());
    if (elapsed_time > 0) {
        printf("Data rate: %.2f KB/s\n", 
               (total_pack_size) / (elapsed_time * 1024.0));
    }
    printf("==============================\n");
}

void PacketPool::set_frame_timeout(std::chrono::milliseconds timeout) {
    frame_timeout_ = timeout;
}