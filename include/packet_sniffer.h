#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <string>
#include <map>
#include <pcap.h>
#include <atomic>

#include "wifi_packet.h"
#include "packet_pool.h"
#include "gamepad_osd.h"

class PacketSniffer {
private:
    pcap_t* handle_;
    PacketPool packet_pool_;

    std::string target_mac_;
    bool filter_by_mac_;
    int link_type_;
    std::atomic<bool> running_;

    // Command line arguments
    std::map<std::string, std::string> args_;

    //multiple wifi card support
    std::vector<pcap_t*> multi_handles_;
    std::vector<std::thread> capture_threads_;
    std::vector<std::string> interfaces_;

    //injection
    void prepare_radiotap_header();
    std::vector<uint8_t> RADIOTAP_HEADER;
    uint8_t _injection_rate = 1; //mbps

    void single_capture_thread(pcap_t* handle, int packet_count);
    bool initialize_pcap(std::string interface);
    bool setup_filter(uint8_t cases,std::string filter_exp);
    void packet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
public:
    PacketSniffer();
    ~PacketSniffer();
    
    bool initialize(std::string interface,uint8_t cases,std::string filter_exp);
    void start_capture(int packet_count);
    void injection_loop();
    void stop_capture();

    // Static callback for pcap_loop
    static void pcap_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, 
                              const u_char* packet);

    // Multi-interface support
    bool initialize_multi(const std::vector<std::string>& interfaces, 
                         uint8_t cases, 
                         const std::string& filter_exp);
    void start_multi_capture(int packet_count = 0);
    void stop_multi_capture();
};

#endif // PACKET_SNIFFER_H