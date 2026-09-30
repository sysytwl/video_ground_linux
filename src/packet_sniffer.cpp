#include "packet_sniffer.h"

#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <thread>

#include "app_log.h"
#include "msp.h"
#include "wifi_inj_sin.h"

namespace {
struct ChannelScanStats {
    int packets = 0;
    int data_frames = 0;
    int version_matches = 0;
    int version_mismatches = 0;
    int missing_radiotap_channel = 0;
    std::set<std::string> data_macs;
    std::set<std::string> matched_macs;
};

struct ScanContext {
    std::set<std::string> macs;
    std::map<std::string, int> device_channels;
    int channel = 0;
    ChannelScanStats* stats = nullptr;
};

struct ScanHandle {
    std::string interface;
    pcap_t* handle = nullptr;
};

std::vector<int> scan_channel_order() {
    std::vector<int> channels;
    for (int channel = 1; channel <= 14; channel++) {
        channels.push_back(channel);
    }
    return channels;
}

uint16_t read_le16(const uint8_t* data) {
    return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
}

int frequency_to_channel(uint16_t frequency) {
    if (frequency == 2484) return 14;
    if (frequency >= 2412 && frequency <= 2472 && (frequency - 2407) % 5 == 0) {
        return (frequency - 2407) / 5;
    }
    return 0;
}

void scan_packet_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto* context = reinterpret_cast<ScanContext*>(user_data);
    if (!context || !packet || pkthdr->caplen < sizeof(ieee80211_radiotap_header)) return;
    if (context->stats) context->stats->packets++;

    ieee80211_radiotap_iterator radiotap_header;
    if (ieee80211_radiotap_iterator_init(&radiotap_header,
        (ieee80211_radiotap_header*)packet,
        pkthdr->caplen) != 0) {
        return;
    }

    int radiotap_channel = 0;
    while (ieee80211_radiotap_iterator_next(&radiotap_header) == 0) {
        if (radiotap_header.this_arg_index == IEEE80211_RADIOTAP_CHANNEL) {
            radiotap_channel = frequency_to_channel(read_le16(radiotap_header.this_arg));
            break;
        }
    }

    const size_t wifi_offset = radiotap_header.max_length;
    if (pkthdr->caplen < wifi_offset + WLAN_IEEE80211_HEADER_SIZE + Air2Ground_Header_Size) return;

    auto* ieee_header = (IEEE80211_MacHeader*)(packet + wifi_offset);
    if (ieee_header->fc.type != 0b10) return;
    const std::string src_mac = WiFiPacket::mac_to_string(ieee_header->addr2);
    if (context->stats) {
        context->stats->data_frames++;
        context->stats->data_macs.insert(src_mac);
    }

    auto* header = (Air2Ground_Header*)(packet + wifi_offset + WLAN_IEEE80211_HEADER_SIZE);
    if (header->packet_version != PACKET_VERSION) {
        if (context->stats) context->stats->version_mismatches++;
        return;
    }

    if (radiotap_channel <= 0 || radiotap_channel > 13) {
        if (context->stats) context->stats->missing_radiotap_channel++;
        app_log("SCAN", "matched_mac=%s ignored invalid_radiotap_channel=%d loop_channel=%d", src_mac.c_str(), radiotap_channel, context->channel);
        return;
    }

    if (context->stats) {
        context->stats->version_matches++;
        context->stats->matched_macs.insert(src_mac);
    }
    context->macs.insert(src_mac);
    context->device_channels[src_mac] = radiotap_channel;
}
}


PacketSniffer::PacketSniffer()
    : filter_by_mac_(false), running_(false), last_scan_match_channel_(DEFAULT_WIFI_CHANNEL) {
}

PacketSniffer::~PacketSniffer() {
    stop_multi_capture();
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
    if (geteuid() == 0) {
        snprintf(command, sizeof(command), "iw dev %s set channel %d", interface, channel);
    } else {
        snprintf(command, sizeof(command), "sudo iw dev %s set channel %d", interface, channel);
    }

    // 方法2: 使用 iwconfig 命令（较旧）
    // snprintf(command, sizeof(command), "sudo iwconfig %s channel %d", interface, channel);

    // 执行系统命令
    int result = system(command);
    if (result == 0) {
        app_log("set_wifi_channel", "成功将接口 %s 切换到信道 %d\n", interface, channel);
        return 0;
    } else {
        app_log("set_wifi_channel", "切换信道失败！请检查接口名称和权限。\n");
        return -1;
    }
}

pcap_t* initialize_pcap(std::string interface) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Method 1: Modern API with immediate mode
    pcap_t* handle_ = pcap_create(interface.c_str(), errbuf);
    if (handle_) {
        // Check if interface supports injection
        if (pcap_can_set_rfmon(handle_) <= 0) {
            std::cerr << "Interface does not support monitor mode/injection" << std::endl;
            pcap_close(handle_);
            handle_ = nullptr;
            return handle_;
        }

        // if (pcap_set_rfmon(handle_, 1) != 0) {
        //     fprintf(stderr, "设置监控模式失败: %s\n", pcap_geterr(handle_));
        //     pcap_close(handle_);
        //     return false;
        // }

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

    // if (handle_ == nullptr) {
    //     std::cerr << "Could not open device " << interface << ": " << errbuf << std::endl;
    //     std::cerr << "\nMake sure:" << std::endl;
    //     std::cerr << "1. Interface " << interface << " exists" << std::endl;
    //     std::cerr << "2. Interface is in monitor mode" << std::endl;
    //     std::cerr << "3. You have root privileges" << std::endl;

    //     // Try to list available devices
    //     pcap_if_t *alldevs;
    //     if (pcap_findalldevs(&alldevs, errbuf) == 0) {
    //         std::cerr << "\nAvailable interfaces:" << std::endl;
    //         for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
    //             std::cerr << "  " << d->name;
    //             if (d->description) {
    //                 std::cerr << " (" << d->description << ")";
    //             }
    //             std::cerr << std::endl;
    //         }
    //         pcap_freealldevs(alldevs);
    //     }
    //     return false;
    // }

    // Get link layer type
    int link_type_ = pcap_datalink(handle_);
    std::cout << "Link type: " << link_type_ << " (";
    if (link_type_ == 127) {
        std::cout << "802.11 with Radiotap header)" << std::endl;
    } else if (link_type_ == 105) {
        std::cout << "802.11 without Radiotap)" << std::endl;
        pcap_close(handle_);
        handle_ = nullptr;
        return handle_;
    } else {
        std::cout << "Unknown - may not be WiFi)" << std::endl;
        pcap_close(handle_);
        handle_ = nullptr;
        return handle_;
    }

    std::cout << "Listening on WiFi interface: " << interface << std::endl;

    return handle_;
}

bool setup_filter(pcap_t* handle_, uint8_t cases,std::string filter_exp) {
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

bool PacketSniffer::initialize_multi(const std::vector<std::string>& interfaces,uint8_t cases, const std::string& filter_exp, int channel) {
    interfaces_ = interfaces;
    const int capture_channel = channel > 0 ? channel : last_scan_match_channel_;

    for (const auto& interface : interfaces) {
        if (interface.empty() || interface == "None") continue;

        app_log("initialize_multi", "capture interface=%s set_channel=%d", interface.c_str(), capture_channel);
        set_wifi_channel(interface.c_str(), capture_channel);

        pcap_t* handle = initialize_pcap(interface.c_str());
            if (handle) {
                // Setup filter for this interface
                if (setup_filter(handle, cases, filter_exp))
                    multi_handles_.push_back(handle);
            }
    }

    return !multi_handles_.empty();
}

#include "video_decoder.h"
void PacketSniffer::start_multi_capture(int packet_count) {
    // Start packet pool processing
    packet_pool_.start_processing(1, video_callback);

    {
        std::lock_guard<std::mutex> lock(seen_packet_mutex_);
        seen_packet_keys_.clear();
    }

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

    {
        std::lock_guard<std::mutex> lock(seen_packet_mutex_);
        seen_packet_keys_.clear();
    }
}

bool PacketSniffer::set_fec(uint8_t k, uint8_t n) {
    return packet_pool_.set_fec(k, n);
}

int PacketSniffer::recommended_wifi_channel() const {
    return recommended_wifi_channel_;
}

int PacketSniffer::recommended_nrf_channel() const {
    const int wifi_center_mhz = 2407 + recommended_wifi_channel_ * 5;
    return std::abs(2525 - wifi_center_mhz) > std::abs(wifi_center_mhz - 2400) ? 125 : 0;
}

std::vector<DiscoveredDevice> PacketSniffer::scan_devices(const std::vector<std::string>& interfaces) {
    ScanContext context;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::vector<ScanHandle> scan_handles;

    for (const auto& interface : interfaces) {
        if (interface.empty() || interface == "None") continue;

        pcap_t* handle = pcap_create(interface.c_str(), errbuf);
        if (!handle) {
            std::cerr << "Could not create scan handle for " << interface << ": " << errbuf << std::endl;
            app_log("SCAN", "create handle failed interface=%s error=%s", interface.c_str(), errbuf);
            continue;
        }

        pcap_set_buffer_size(handle, 128 * 1024);
        pcap_set_timeout(handle, 10);
        pcap_set_immediate_mode(handle, 1);
        pcap_set_promisc(handle, 1);
        pcap_set_snaplen(handle, BUFSIZ);

        if (pcap_activate(handle) != 0) {
            std::cerr << "Could not activate scan handle for " << interface << ": " << pcap_geterr(handle) << std::endl;
            app_log("SCAN", "activate handle failed interface=%s error=%s", interface.c_str(), pcap_geterr(handle));
            pcap_close(handle);
            continue;
        }

        if (pcap_datalink(handle) != 127) {
            app_log("SCAN", "skip interface=%s unsupported datalink=%d", interface.c_str(), pcap_datalink(handle));
            pcap_close(handle);
            continue;
        }

        if (pcap_setnonblock(handle, 1, errbuf) != 0) {
            app_log("SCAN", "nonblock failed interface=%s error=%s", interface.c_str(), errbuf);
        }

        scan_handles.push_back({interface, handle});
    }

    app_log("SCAN", "start interfaces=%zu channel_order=1-13", scan_handles.size());

    constexpr auto channel_settle = std::chrono::milliseconds(15);
    constexpr auto channel_dwell = std::chrono::milliseconds(70);
    int last_matched_channel = 0;
    int lowest_traffic_channel = DEFAULT_WIFI_CHANNEL;
    int lowest_packet_count = std::numeric_limits<int>::max();
    for (int channel : scan_channel_order()) {
        ChannelScanStats stats;
        context.channel = channel;
        context.stats = &stats;

        for (const auto& scan_handle : scan_handles) {
            set_wifi_channel(scan_handle.interface.c_str(), channel);
        }

        std::this_thread::sleep_for(channel_settle);
        const auto deadline = std::chrono::steady_clock::now() + channel_dwell;
        while (std::chrono::steady_clock::now() < deadline) {
            for (const auto& scan_handle : scan_handles) {
                int dispatched = pcap_dispatch(scan_handle.handle, 128, scan_packet_callback, reinterpret_cast<u_char*>(&context));
                if (dispatched < 0) {
                    app_log("SCAN", "dispatch failed channel=%d interface=%s error=%s", channel, scan_handle.interface.c_str(), pcap_geterr(scan_handle.handle));
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        std::cout << "Scan channel " << channel
                  << ": packets=" << stats.packets
                  << " data=" << stats.data_frames
                  << " data_macs=" << stats.data_macs.size()
                  << " version_matches=" << stats.version_matches
                  << " matched_macs=" << stats.matched_macs.size()
                  << " no_rt_channel=" << stats.missing_radiotap_channel
                  << " mismatches=" << stats.version_mismatches
                  << std::endl;

        app_log("SCAN", "channel=%d packets=%d data=%d data_macs=%zu version_matches=%d matched_macs=%zu no_rt_channel=%d mismatches=%d",
            channel,
            stats.packets,
            stats.data_frames,
            stats.data_macs.size(),
            stats.version_matches,
            stats.matched_macs.size(),
            stats.missing_radiotap_channel,
            stats.version_mismatches);

        for (const auto& matched_mac : stats.matched_macs) {
            app_log("SCAN", "channel=%d matched_mac=%s", channel, matched_mac.c_str());
        }
        if (!stats.matched_macs.empty()) {
            last_matched_channel = channel;
        }
        if (stats.packets < lowest_packet_count) {
            lowest_packet_count = stats.packets;
            lowest_traffic_channel = channel;
        }
    }

    context.stats = nullptr;
    if (last_matched_channel != 0) {
        last_scan_match_channel_ = last_matched_channel;
    }
    recommended_wifi_channel_ = lowest_traffic_channel;
    for (const auto& scan_handle : scan_handles) {
        pcap_close(scan_handle.handle);
    }

    app_log("SCAN", "done matched_unique_macs=%zu selected_channel=%d", context.macs.size(), last_scan_match_channel_);
    std::vector<DiscoveredDevice> devices;
    for (const auto& [mac, channel] : context.device_channels) {
        devices.push_back({mac, channel});
        app_log("SCAN", "device mac=%s channel=%d", mac.c_str(), channel);
    }
    return devices;
}

void PacketSniffer::packet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    ieee80211_radiotap_iterator radiotap_header;
    if (ieee80211_radiotap_iterator_init(&radiotap_header, (ieee80211_radiotap_header*)packet, pkthdr->caplen) != 0) return;

    const size_t wifi_offset = radiotap_header.max_length;
    if (pkthdr->caplen < wifi_offset + WLAN_IEEE80211_HEADER_SIZE + Air2Ground_Header_Size) return;

    auto* ieee_header = (IEEE80211_MacHeader*)(packet + wifi_offset);
    if (ieee_header->fc.type != 0b10) return;//return non data pack

    auto* header = (Air2Ground_Header*)(packet + wifi_offset + WLAN_IEEE80211_HEADER_SIZE);
    if (header->packet_version != PACKET_VERSION) return;
    if (header->type == Air2Ground_Header::Type::SerialData) {
        const size_t serial_offset = wifi_offset + WLAN_IEEE80211_HEADER_SIZE + Air2Ground_Header_Size;
        if (pkthdr->caplen < serial_offset + sizeof(Air2Ground_Serial_Packet)) return;
        auto* serial = reinterpret_cast<const Air2Ground_Serial_Packet*>(packet + serial_offset);
        const size_t payload_offset = serial_offset + sizeof(Air2Ground_Serial_Packet);
        if (serial->payload_length > 256 || pkthdr->caplen < payload_offset + serial->payload_length) return;
        msp_feed_rx(packet + payload_offset, serial->payload_length);
        return;
    }
    if (header->type != Air2Ground_Header::Type::Video) return;

    const uint64_t packet_key = (static_cast<uint64_t>(header->frame_index) << 8) | header->part_index;
    {
        std::lock_guard<std::mutex> lock(seen_packet_mutex_);
        if (seen_packet_keys_.size() > 8192) seen_packet_keys_.clear();
        if (!seen_packet_keys_.insert(packet_key).second) return;
    }

    packet_pool_.add_packet(packet, pkthdr->caplen);
}

// Static callback function for pcap_loop
void PacketSniffer::pcap_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(user_data);
    sniffer->packet_handler(pkthdr, packet);
}

// Function to discover interfaces
std::vector<std::string> discover_interfaces() {
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            interfaces.push_back(d->name);
        }
        pcap_freealldevs(alldevs);
    }
    return interfaces;
}

// #include "ieee80211_radiotap.h"

// static void radiotap_add_u8(uint8_t*& dst, size_t& idx, uint8_t data){
//     *dst++ = data;
//     idx++;
// }

// static void radiotap_add_u16(uint8_t*& dst, size_t& idx, uint16_t data){
//     if ((idx & 1) == 1) //not aligned, pad first
//     {
//         radiotap_add_u8(dst, idx, 0);
//     }
//     *reinterpret_cast<uint16_t*>(dst) = data;
//     dst += 2;
//     idx += 2;
// }

// void prepare_radiotap_header(std::vector<uint8_t> RADIOTAP_HEADER){
//     RADIOTAP_HEADER.clear();
//     RADIOTAP_HEADER.resize(1024);
//     ieee80211_radiotap_header& hdr = reinterpret_cast<ieee80211_radiotap_header& >(*RADIOTAP_HEADER.data());
//     hdr.it_version = 0;
//     hdr.it_present = 0;

//     auto* dst = RADIOTAP_HEADER.data() + sizeof(ieee80211_radiotap_header);
//     size_t idx = dst - RADIOTAP_HEADER.data();

//     //| (1 << IEEE80211_RADIOTAP_RATE)
//     //radiotap_add_u8(dst, idx, _injection_rate*2);//500kpbs
//     hdr.it_present |= (1 << IEEE80211_RADIOTAP_TX_FLAGS);
//     radiotap_add_u16(dst, idx, IEEE80211_RADIOTAP_F_TX_NOACK); //used to be 0x18
//     //| (1 << IEEE80211_RADIOTAP_RTS_RETRIES)
//     //radiotap_add_u8(dst, idx, 0x0);
//     hdr.it_present |= (1 << IEEE80211_RADIOTAP_DATA_RETRIES);
//     radiotap_add_u8(dst, idx, 0x0);
//     //| (1 << IEEE80211_RADIOTAP_CHANNEL)
//     // radiotap_add_u16(dst, idx, CH13_FREQ);
//     // radiotap_add_u16(dst, idx, 0);
//     hdr.it_present |= (1 << IEEE80211_RADIOTAP_MCS);
//     radiotap_add_u8(dst, idx, IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI ); // short gI
//     radiotap_add_u8(dst, idx, IEEE80211_RADIOTAP_MCS_BW_20 );  //HT20
//     radiotap_add_u8(dst, idx, 0);  //MCS Index 1 13M

//     //finish it
//     hdr.it_len = static_cast<__le16>(idx);
//     RADIOTAP_HEADER.resize(idx);
// }

// #include "wifi_inj_sin.h"

// uint32_t calculate_fcs(const uint8_t *data, size_t len) {
//     uint32_t crc = 0xFFFFFFFF;

//     for (size_t i = 0; i < len; i++) {
//         crc ^= data[i];
//         for (int j = 0; j < 8; j++) {
//             if (crc & 1) {
//                 crc = (crc >> 1) ^ 0xEDB88320;
//             } else {
//                 crc >>= 1;
//             }
//         }
//     }

//     return ~crc;
// }
// void injection_loop() {
//     const int injection_rate_hz = 60;
//     const auto injection_interval = std::chrono::milliseconds(1000 / injection_rate_hz);


//     uint8_t* injection_packet;
//     injection_packet = (uint8_t*)malloc(1600);
//     Ground2Air_Data_Packet payload;
//     payload.packet_version = PACKET_VERSION;
//     while (running_) {
//         size_t packet_size = 0;

//         // Add Radiotap header
//         prepare_radiotap_header();
//         memcpy(injection_packet,RADIOTAP_HEADER.data(),RADIOTAP_HEADER.size());
//         packet_size += RADIOTAP_HEADER.size();

//         // IEEE header
//         memcpy(injection_packet+packet_size,&WLAN_IEEE_HEADER_GROUND2AIR[0], WLAN_IEEE_HEADER_SIZE);
//         packet_size += WLAN_IEEE_HEADER_SIZE;

//         //DATA test payload
//         payload.type = Ground2Air_Data_Packet::Type::Telemetry;
//         gamepad.update();
//         payload.channel_data[0] = 1000+66*(gamepad.get_axis(2) + 32767);
//         payload.channel_data[1] =  1000+66*(gamepad.get_axis(3) + 32767);
//         payload.channel_data[2] =  1000+66*(gamepad.get_axis(0) + 32767);
//         payload.channel_data[3] =  1000+66*(gamepad.get_axis(1) + 32767);
//         payload.channel_data_1[0] = 0;
//         memcpy(injection_packet+packet_size, &payload, sizeof(Ground2Air_Data_Packet));
//         packet_size += sizeof(Ground2Air_Data_Packet);

//         //pcap_inject(handle_, injection_packet, packet_size);

//         std::this_thread::sleep_for(injection_interval);
//     }
// }
