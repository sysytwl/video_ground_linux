#include "packet_sniffer.h"
#include "wifi_inj_sin.h"
#include "radiotap.h"
#include "video_decoder.h"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>
#include <iomanip>



PacketSniffer::PacketSniffer() 
    : handle_(nullptr), filter_by_mac_(false), link_type_(0), running_(false) {
}

PacketSniffer::~PacketSniffer() {
    stop_capture();
    if (handle_) {
        pcap_close(handle_);
    }
}

bool PacketSniffer::initialize(std::string interface,uint8_t cases,std::string filter_exp) {
    // Initialize pcap
    if (!initialize_pcap(interface)) {
        return false;
    }
    
    //Set up filter
    if (!setup_filter(cases,filter_exp)) {
       return false;
    }
    
    return true;
}

bool PacketSniffer::initialize_pcap(std::string interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Method 1: Modern API with immediate mode
    handle_ = pcap_create(interface.c_str(), errbuf);
    if (handle_) {
        // WiFi works better with small buffer and short timeout
        pcap_set_buffer_size(handle_, 128 * 1024);  // 128KB
        pcap_set_timeout(handle_, 10);  // 10ms for WiFi
        
        // Try immediate mode first
        if (pcap_set_immediate_mode(handle_, 1) == 0) {
            printf("Immediate mode enabled\n");
        } else {
            printf("Immediate mode not available, using 10ms timeout\n");
        }
        
        pcap_set_promisc(handle_, 1);
        pcap_set_snaplen(handle_, BUFSIZ);
        
        if (pcap_activate(handle_) != 0) {
            pcap_close(handle_);

            // Method 2: Fallback to traditional API
            printf("Using traditional pcap_open_live with 10ms timeout\n");
            handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 10, errbuf);
        }
        
    }


    if (handle_ == nullptr) {
        std::cerr << "Could not open device " << interface << ": " << errbuf << std::endl;
        std::cerr << "\nMake sure:" << std::endl;
        std::cerr << "1. Interface " << interface << " exists" << std::endl;
        std::cerr << "2. Interface is in monitor mode" << std::endl;
        std::cerr << "3. You have root privileges" << std::endl;
        
        // Try to list available devices
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == 0) {
            std::cerr << "\nAvailable interfaces:" << std::endl;
            for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
                std::cerr << "  " << d->name;
                if (d->description) {
                    std::cerr << " (" << d->description << ")";
                }
                std::cerr << std::endl;
            }
            pcap_freealldevs(alldevs);
        }
        return false;
    }
    
    // Get link layer type
    link_type_ = pcap_datalink(handle_);
    std::cout << "Link type: " << link_type_ << " (";
    if (link_type_ == 127) {
        std::cout << "802.11 with Radiotap header)" << std::endl;
    } else if (link_type_ == 105) {
        std::cout << "802.11 without Radiotap)" << std::endl;
    } else {
        std::cout << "Unknown - may not be WiFi)" << std::endl;
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    
    std::cout << "Listening on WiFi interface: " << interface << std::endl;
    return true;
}

bool PacketSniffer::setup_filter(uint8_t cases,std::string filter_exp) {
    struct bpf_program fp;

    if (cases==0) {
        if (pcap_compile(handle_, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Could not parse filter: " << pcap_geterr(handle_) << std::endl;
            return false;
        }

        if (pcap_setfilter(handle_, &fp) == -1) {
            std::cerr << "Could not install filter: " << pcap_geterr(handle_) << std::endl;
            return false;
        }
        std::cout << "BPF filter set to: " << filter_exp << std::endl;
        pcap_freecode(&fp);
    } else if (cases==1) {
        // Remove colons from MAC for BPF filter
        WiFiPacket::remove_char(filter_exp, ':');

        // WiFi-specific BPF filter: wlan addr2 is the transmitter MAC
        std::string mac_filter = "wlan addr2 " + filter_exp;

        if (pcap_compile(handle_, &fp, mac_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Could not parse filter: " << pcap_geterr(handle_) << std::endl;
            return false;
        }
        
        if (pcap_setfilter(handle_, &fp) == -1) {
            std::cerr << "Could not install filter: " << pcap_geterr(handle_) << std::endl;
            return false;
        }
        std::cout << "WiFi BPF filter set to: " << mac_filter << std::endl;
        pcap_freecode(&fp);
    }
    
    return true;
}

void PacketSniffer::packet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    //clock_t start = clock();

    PacketInfo info;
    info.header = *pkthdr;

    size_t offset = 0;

    // Parse Radiotap header if present
    if (link_type_ == 127) {  // DLT_IEEE802_11_RADIO = 127
        offset = parse_header(packet, pkthdr->caplen, info.radiotapinfo);
        // if (offset == 0 || offset >= pkthdr->caplen) {
        //     return;  // Failed to parse or no data left
        // }
        info.wifi_header_offset = offset;
    } else {
        info.wifi_header_offset = 0;
    }

    // Parse 802.11 header
    if (!WiFiPacket::parse_80211_header(packet + offset, pkthdr->caplen - offset, info)) {
        return;  // Not a valid WiFi packet
    }
    
    // // Check if we should filter by MAC
    // if (filter_by_mac_ && !target_mac_.empty()) {
    //     if (!WiFiPacket::mac_matches(info.src_mac, target_mac_)) {
    //         return;  // Skip packets not from target MAC
    //     }
    // }

    if (!info.is_data_frame){
        std::cout << "wrong frame type, plz set the filter!" << std::endl;
        return;
    }

    Air2Ground_Header* header = (Air2Ground_Header*)(packet + offset + WLAN_IEEE80211_HEADER_SIZE);
    if(header->packet_version != PACKET_VERSION) {
        std::cout << "Wrong pack Version" << std::endl;
        return;
    }

    if (header->type == Air2Ground_Header::Type::Video) {
        Air2Ground_Video_Packet* video_header = (Air2Ground_Video_Packet*)header;
        
        uint32_t frame_index = video_header->frame_index;
        uint8_t part_index = video_header->part_index;

        // Add to pool
        packet_pool_.add_packet(
            frame_index,
            part_index, 
            (uint8_t*)(video_header)+Air2Ground_Video_Packet_Header_Size,
            pkthdr->caplen - offset - WLAN_IEEE80211_HEADER_SIZE - Air2Ground_Video_Packet_Header_Size,
            video_header->last_part
        );
    }

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

    //clock_t end = clock();
    //printf("Callback took: %ld us  \n ", (end-start)*1000000/CLOCKS_PER_SEC);
}

void PacketSniffer::start_capture(int packet_count) {
    // Start packet pool processing thread
    packet_pool_.start_processing(1,video_callback,(void*)nullptr);
    
    std::cout << "\nStarting WiFi packet capture..." << std::endl;
    std::cout << "Press Ctrl+C to stop\n" << std::endl;
    
    running_ = true;
    
    // Start capture loop (block thread)
    //pcap_set_buffer_size(handle_, 64 * 1024 * 1024); // 64MB
    int result = pcap_loop(handle_, packet_count,PacketSniffer::pcap_callback, (u_char*)this);
    
    if (result == -1) {
        std::cerr << "Error in pcap_loop: " << pcap_geterr(handle_) << std::endl;
    } else if (result == -2) {
        std::cout << "Capture stopped by pcap_breakloop" << std::endl;
    } else if (result == 0 && packet_count > 0) {
        std::cout << "Capture completed (reached packet count limit)" << std::endl;
    }
}

void PacketSniffer::stop_capture() {
    running_ = false;
    if (handle_) {
        pcap_breakloop(handle_);
    }
    packet_pool_.stop_processing();
}

// Static callback function for pcap_loop
void PacketSniffer::pcap_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(user_data);
    sniffer->packet_handler(pkthdr, packet);
}