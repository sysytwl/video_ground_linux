#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <string>
#include <map>
#include <pcap.h>
#include <atomic>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

#include "wifi_packet.h"
#include "packet_pool.h"

struct DiscoveredDevice {
    std::string mac;
    int channel = 0;
};

class PacketSniffer {
private:
    PacketPool packet_pool_;

    std::string target_mac_;
    bool filter_by_mac_;

    std::atomic<bool> running_;

    // Command line arguments
    std::map<std::string, std::string> args_;

    //multiple wifi card support
    std::vector<pcap_t*> multi_handles_;
    std::vector<std::thread> capture_threads_;
    std::vector<std::string> interfaces_;
    int last_scan_match_channel_;
    int recommended_wifi_channel_ = 13;
    std::mutex seen_packet_mutex_;
    std::unordered_set<uint64_t> seen_packet_keys_;

    void single_capture_thread(pcap_t* handle, int packet_count);
    void packet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
public:
    PacketSniffer();
    ~PacketSniffer();

    // Static callback for pcap_loop
    static void pcap_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, 
                              const u_char* packet);

    // Multi-interface support
    bool initialize_multi(const std::vector<std::string>& interfaces, 
                         uint8_t cases, 
                         const std::string& filter_exp,
                         int channel);
    void start_multi_capture(int packet_count = 0);
    void stop_multi_capture();
    bool set_fec(uint8_t k, uint8_t n);
    int recommended_wifi_channel() const;
    int recommended_nrf_channel() const;
    std::vector<DiscoveredDevice> scan_devices(const std::vector<std::string>& interfaces);
};

// Function to discover interfaces
std::vector<std::string> discover_interfaces();

#endif // PACKET_SNIFFER_H