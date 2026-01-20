#ifndef WIFI_PACKET_H
#define WIFI_PACKET_H
#include "radiotap.h"
#include <string>
#include <vector>
#include <cstdint>
#include <pcap.h>

#pragma pack(push, 1)
struct FrameControl {
    uint16_t protocol_version:2;
    uint16_t type:2;           // 00=Management, 01=Control, 10=Data
    uint16_t subtype:4;
    uint16_t to_ds:1;
    uint16_t from_ds:1;
    uint16_t more_fragments:1;
    uint16_t retry:1;
    uint16_t power_management:1;
    uint16_t more_data:1;
    uint16_t protected_frame:1;
    uint16_t order:1;
};

struct IEEE80211_MacHeader {
    FrameControl fc;
    uint16_t duration;
    uint8_t addr1[6];  // Receiver
    uint8_t addr2[6];  // Transmitter (Source)
    uint8_t addr3[6];  // Destination or BSSID
    uint16_t sequence_control;
};
constexpr size_t WLAN_IEEE80211_HEADER_SIZE = sizeof(IEEE80211_MacHeader);
static_assert(WLAN_IEEE80211_HEADER_SIZE == 24, "");
#pragma pack(pop)

struct PacketInfo {
    struct pcap_pkthdr header;
    uint8_t *data;
    size_t data_len;
    std::string src_mac;     // Transmitter MAC (addr2)
    std::string dst_mac;     // Receiver MAC (addr1)
    std::string bssid_mac;   // BSSID (addr3)
    uint16_t frame_type;
    uint16_t frame_subtype;
    bool is_data_frame;
    bool is_protected;
    size_t wifi_header_offset;
    
    // Constructor
    PacketInfo() : frame_type(0), frame_subtype(0), 
                   is_data_frame(false), is_protected(false), 
                   wifi_header_offset(0) {}
};

namespace WiFiPacket {
    // Utility functions
    std::string mac_to_string(const uint8_t* mac_bytes);
    std::string normalize_mac(const std::string& mac);
    bool mac_matches(const std::string& mac1, const std::string& mac2);
    bool parse_80211_header(const uint8_t* packet, uint32_t length, PacketInfo& info);
    std::string get_frame_type_string(uint8_t type, uint8_t subtype);
    void remove_char(std::string& str, char ch);
}

#endif // WIFI_PACKET_H