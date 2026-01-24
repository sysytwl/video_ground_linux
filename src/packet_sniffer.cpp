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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int set_wifi_channel(const char *interface, int channel) {
    char command[256];

// void Comms::setChannel(int ch)
// {
//     for (const auto& itf:m_rx_descriptor.interfaces)  //the list contains both RX and TX interfaces
//     {
//         system(fmt::format("iwconfig {} channel {}", itf, ch).c_str());
//     }
// }

    // 方法1: 使用 iw 命令（推荐）
    snprintf(command, sizeof(command), "sudo iw dev %s set channel %d", interface, channel);

    // 方法2: 使用 iwconfig 命令（较旧）
    // snprintf(command, sizeof(command), "sudo iwconfig %s channel %d", interface, channel);

    // 执行系统命令
    int result = system(command);
    if (result == 0) {
        printf("成功将接口 %s 切换到信道 %d\n", interface, channel);
        return 0;
    } else {
        fprintf(stderr, "切换信道失败！请检查接口名称和权限。\n");
        return -1;
    }
}

bool PacketSniffer::initialize_pcap(std::string interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Method 1: Modern API with immediate mode
    handle_ = pcap_create(interface.c_str(), errbuf);
    if (handle_) {
        // Check if interface supports injection
        if (pcap_can_set_rfmon(handle_) <= 0) {
            std::cerr << "Interface does not support monitor mode/injection" << std::endl;
            pcap_close(handle_);
            handle_ = nullptr;
            return false;
        }

        if (pcap_set_rfmon(handle_, 1) != 0) {
            fprintf(stderr, "设置监控模式失败: %s\n", pcap_geterr(handle_));
            pcap_close(handle_);
            return false;
        }

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

bool PacketSniffer::initialize_multi(const std::vector<std::string>& interfaces,uint8_t cases, const std::string& filter_exp) {
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
    packet_pool_.start_processing(1, video_callback);
    
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
                          PacketSniffer::pcap_callback,
                          (u_char*)this);
    
    if (result == -1) {
        std::cerr << "Error in pcap_loop: " << pcap_geterr(handle) << std::endl;
    }
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

std::thread _injection_thread;

void PacketSniffer::start_capture(int packet_count) {
    // Start packet pool processing thread
    packet_pool_.start_processing(1,video_callback);

    std::cout << "Press Ctrl+C to stop\n" << std::endl;

    running_ = true;

    _injection_thread = std::thread(&PacketSniffer::injection_loop, this);

    // Start capture loop (block thread)
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

    if(_injection_thread.joinable())
        _injection_thread.join();

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

#include "ieee80211_radiotap.h"
// 信道频率表（2.4 GHz频段）
#define CH1_FREQ  2412  // 信道1: 2.412 GHz
#define CH6_FREQ  2437  // 信道6: 2.437 GHz
#define CH11_FREQ 2462  // 信道11: 2.462 GHz
#define CH13_FREQ 2472  // 信道13: 2.472 GHz

static void radiotap_add_u8(uint8_t*& dst, size_t& idx, uint8_t data)
{
    *dst++ = data;
    idx++;
}

static void radiotap_add_u16(uint8_t*& dst, size_t& idx, uint16_t data)
{
    if ((idx & 1) == 1) //not aligned, pad first
    {
        radiotap_add_u8(dst, idx, 0);
    }
    *reinterpret_cast<uint16_t*>(dst) = data;
    dst += 2;
    idx += 2;
}

void PacketSniffer::prepare_radiotap_header(){
    RADIOTAP_HEADER.resize(1024);
    ieee80211_radiotap_header& hdr = reinterpret_cast<ieee80211_radiotap_header& >(*RADIOTAP_HEADER.data());
    hdr.it_version = 0;
    hdr.it_present = 0
        //| (1 << IEEE80211_RADIOTAP_RATE)
        | (1 << IEEE80211_RADIOTAP_TX_FLAGS)
        //| (1 << IEEE80211_RADIOTAP_RTS_RETRIES)
        | (1 << IEEE80211_RADIOTAP_DATA_RETRIES)
        //| (1 << IEEE80211_RADIOTAP_CHANNEL)
        | (1 << IEEE80211_RADIOTAP_MCS);

    auto* dst = RADIOTAP_HEADER.data() + sizeof(ieee80211_radiotap_header);
    size_t idx = dst - RADIOTAP_HEADER.data();

    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_RATE))
        radiotap_add_u8(dst, idx, _injection_rate*2);//500kpbs
    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_TX_FLAGS))
        radiotap_add_u16(dst, idx, IEEE80211_RADIOTAP_F_TX_NOACK); //used to be 0x18
    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_RTS_RETRIES))
        radiotap_add_u8(dst, idx, 0x0);
    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_DATA_RETRIES))
        radiotap_add_u8(dst, idx, 0x0);
    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_MCS))
    {
        radiotap_add_u8(dst, idx, IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI ); // short gI
        radiotap_add_u8(dst, idx, IEEE80211_RADIOTAP_MCS_BW_20 );  //HT20
        radiotap_add_u8(dst, idx, 1);  //MCS Index 1 13M
    }
    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_CHANNEL))
    {
        radiotap_add_u16(dst, idx, CH13_FREQ);
        radiotap_add_u16(dst, idx, 0);
    }

    //finish it
    hdr.it_len = static_cast<__le16>(idx);
    RADIOTAP_HEADER.resize(idx);
}

#include "wifi_inj_sin.h"

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

#include "gamepad_osd.h"
extern GamepadHandler gamepad;

void PacketSniffer::injection_loop() {
    const int injection_rate_hz = 60;
    const auto injection_interval = std::chrono::milliseconds(1000 / injection_rate_hz);

    std::vector<uint8_t> injection_packet;
    while (running_) {
        injection_packet.clear();

        // Add Radiotap header
        prepare_radiotap_header();
        injection_packet.insert(injection_packet.end(), RADIOTAP_HEADER.begin(), RADIOTAP_HEADER.end());

        // IEEE header
        injection_packet.insert(injection_packet.end(), WLAN_IEEE_HEADER_AIR2GROUND, WLAN_IEEE_HEADER_AIR2GROUND+WLAN_IEEE_HEADER_SIZE);

        //DATA test payload
        //GamepadState state = gamepad.get_state();
        //uint16_t controller_channels[12] = {0};
        injection_packet.insert(injection_packet.end(), WLAN_IEEE_HEADER_AIR2GROUND, WLAN_IEEE_HEADER_AIR2GROUND+WLAN_IEEE_HEADER_SIZE);

        int result = pcap_inject(handle_, injection_packet.data(), injection_packet.size());
        std::cout << "INJECTION RESULT: " << result << std::endl;

        std::this_thread::sleep_for(injection_interval);
    }
}
