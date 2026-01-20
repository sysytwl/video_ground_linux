#include "packet_sniffer.h"

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

bool PacketSniffer::initialize_multi(const std::vector<std::string>& interfaces,
                                    uint8_t cases, 
                                    const std::string& filter_exp) {
    interfaces_ = interfaces;
    
    for (const auto& interface : interfaces) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_create(interface.c_str(), errbuf);
        
        if (handle) {
            pcap_set_buffer_size(handle, 128 * 1024);
            pcap_set_timeout(handle, 10);
            pcap_set_promisc(handle, 1);
            pcap_set_snaplen(handle, BUFSIZ);
            
            if (pcap_activate(handle) != 0) {
                pcap_close(handle);
                handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 10, errbuf);
            }
            
            if (handle) {
                // Setup filter for this interface
                struct bpf_program fp;
                std::string actual_filter = filter_exp;
                
                if (cases == 1 && !filter_exp.empty()) {
                    WiFiPacket::remove_char(actual_filter, ':');
                    actual_filter = "wlan addr2 " + actual_filter;
                }
                
                if (pcap_compile(handle, &fp, actual_filter.c_str(), 0, 
                                 PCAP_NETMASK_UNKNOWN) == 0) {
                    pcap_setfilter(handle, &fp);
                    pcap_freecode(&fp);
                }
                
                multi_handles_.push_back(handle);
                std::cout << "Initialized interface: " << interface << std::endl;
            }
        }
    }
    
    return !multi_handles_.empty();
}

#include "video_decoder.h"
void PacketSniffer::start_multi_capture(int packet_count) {
    // Start packet pool processing
    packet_pool_.start_processing(2, video_callback, nullptr); // 2 threads
    
    std::cout << "\nStarting multi-interface capture on " 
              << multi_handles_.size() << " interfaces..." << std::endl;
    
    running_ = true;
    
    // Start a capture thread for each interface
    for (auto handle : multi_handles_) {
        capture_threads_.emplace_back(&PacketSniffer::single_capture_thread, 
                                       this, handle, packet_count);
    }
}

void PacketSniffer::single_capture_thread(pcap_t* handle, int packet_count) {
    int result = pcap_loop(handle, packet_count, 
                          PacketSniffer::pcap_callback_multi, 
                          (u_char*)this);
    
    if (result == -1) {
        std::cerr << "Error in pcap_loop: " << pcap_geterr(handle) << std::endl;
    }
}

void PacketSniffer::pcap_callback_multi(u_char* user_data, 
                                        const struct pcap_pkthdr* pkthdr, 
                                        const u_char* packet) {
    PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(user_data);
    sniffer->packet_handler(pkthdr, packet);
}

void PacketSniffer::stop_multi_capture() {
    running_ = false;
    
    // Break all pcap loops
    for (auto handle : multi_handles_) {
        pcap_breakloop(handle);
    }
    
    // Wait for all threads
    for (auto& thread : capture_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    capture_threads_.clear();
    
    // Close all handles
    for (auto handle : multi_handles_) {
        pcap_close(handle);
    }
    multi_handles_.clear();
    
    // Stop packet pool
    packet_pool_.stop_processing();
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
    // Add to pool
    packet_pool_.add_packet(packet, pkthdr->caplen);
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