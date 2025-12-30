#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <string>
#include <map>
#include <pcap.h>
#include <atomic>
#include "wifi_packet.h"
#include "packet_pool.h"

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
    
    // Helper methods
    bool initialize_pcap(std::string interface);
    bool setup_filter(uint8_t cases,std::string filter_exp);
    void parse_args(int argc, char* argv[]);
    void packet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
public:
    PacketSniffer();
    ~PacketSniffer();
    
    bool initialize(std::string interface,uint8_t cases,std::string filter_exp);
    void start_capture(int packet_count);
    void stop_capture();

    // Static callback for pcap_loop
    static void pcap_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, 
                              const u_char* packet);
};

#endif // PACKET_SNIFFER_H