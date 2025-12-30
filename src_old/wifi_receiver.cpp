#include <iostream>
#include <pcap.h>
#include <cstring>
#include "packet_format.h"

class WifiReceiver {
private:
    pcap_t* handle;
    const uint8_t target_mac[6];
    bool running;

public:
    WifiReceiver(const char* iface, const uint8_t* mac) : running(false) {
        memcpy(target_mac, mac, 6);
        
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "Couldn't open device " << iface << ": " << errbuf << std::endl;
            exit(EXIT_FAILURE);
        }

        // 设置802.11数据帧过滤
        struct bpf_program fp;
        std::string filter_exp = "wlan type data";
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
            exit(EXIT_FAILURE);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    ~WifiReceiver() {
        if (handle) pcap_close(handle);
    }

    void start(std::function<void(Air2Ground_Header*, size_t)> callback) {
        running = true;
        while (running) {
            struct pcap_pkthdr header;
            const u_char* packet = pcap_next(handle, &header);
            if (!packet) continue;

            // 跳过802.11头部，提取有效载荷
            if (header.len < WLAN_IEEE_HEADER_SIZE) continue;
            
            auto* payload = (Air2Ground_Header*)(packet + WLAN_IEEE_HEADER_SIZE);
            callback(payload, header.len - WLAN_IEEE_HEADER_SIZE);
        }
    }

    void stop() {
        running = false;
    }
};