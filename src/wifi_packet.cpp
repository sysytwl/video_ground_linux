#include "wifi_packet.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <iostream>

std::string WiFiPacket::mac_to_string(const uint8_t* mac_bytes) {
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_bytes[0], mac_bytes[1], mac_bytes[2],
             mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    return std::string(mac_str);
}

std::string WiFiPacket::normalize_mac(const std::string& mac) {
    std::string result;
    for (char c : mac) {
        if (c != ':' && c != '-') {
            result += std::tolower(c);
        }
    }
    // Reformat as colon-separated
    if (result.length() == 12) {
        return result.substr(0, 2) + ":" + result.substr(2, 2) + ":" +
               result.substr(4, 2) + ":" + result.substr(6, 2) + ":" +
               result.substr(8, 2) + ":" + result.substr(10, 2);
    }
    return mac;  // Return original if can't normalize
}

bool WiFiPacket::mac_matches(const std::string& mac1, const std::string& mac2) {
    if (mac2.empty()) return true;  // Empty MAC means "all"
    
    std::string norm1, norm2;
    for (char c : mac1) {
        if (c != ':' && c != '-') norm1 += std::tolower(c);
    }
    for (char c : mac2) {
        if (c != ':' && c != '-') norm2 += std::tolower(c);
    }
    return norm1 == norm2;
}

bool WiFiPacket::parse_80211_header(const uint8_t* packet, uint32_t length, PacketInfo& info) {
    if (length < sizeof(IEEE80211_MacHeader)) {
        return false;
    }
    
    IEEE80211_MacHeader* hdr = (IEEE80211_MacHeader*)packet;
    
    // Extract frame control field
    uint16_t frame_control = *((uint16_t*)&hdr->fc);
    info.frame_type = (frame_control >> 2) & 0x03;      // Bits 2-3: Type
    //info.frame_subtype = (frame_control >> 4) & 0x0F;   // Bits 4-7: Subtype
    info.is_data_frame = (info.frame_type == 0x02);     // Type 2 = Data frame
    //info.is_protected = hdr->fc.protected_frame;        // WEP/WPA/WPA2
    
    // Extract MAC addresses from WiFi header
    //info.src_mac = mac_to_string(hdr->addr2);
    //info.dst_mac = mac_to_string(hdr->addr1);
    //info.bssid_mac = mac_to_string(hdr->addr3);
    
    return true;
}

std::string WiFiPacket::get_frame_type_string(uint8_t type, uint8_t subtype) {
    std::string result;
    switch (type) {
        case 0:  // Management
            result = "Mgmt";
            switch (subtype) {
                case 0x00: result += " (Assoc Req)"; break;
                case 0x01: result += " (Assoc Resp)"; break;
                case 0x02: result += " (Reassoc Req)"; break;
                case 0x03: result += " (Reassoc Resp)"; break;
                case 0x04: result += " (Probe Req)"; break;
                case 0x05: result += " (Probe Resp)"; break;
                case 0x08: result += " (Beacon)"; break;
                case 0x0A: result += " (Disassoc)"; break;
                case 0x0B: result += " (Auth)"; break;
                case 0x0C: result += " (Deauth)"; break;
                default: result += " (Other)"; break;
            }
            break;
        case 1:  // Control
            result = "Ctrl";
            switch (subtype) {
                case 0x0B: result += " (RTS)"; break;
                case 0x0C: result += " (CTS)"; break;
                case 0x0D: result += " (ACK)"; break;
                default: result += " (Other)"; break;
            }
            break;
        case 2:  // Data
            result = "Data";
            if (subtype & 0x08) result += " (QoS)";
            break;
        default:
            result = "Unknown";
            break;
    }
    return result;
}

void WiFiPacket::remove_char(std::string& str, char ch) {
    str.erase(std::remove(str.begin(), str.end(), ch), str.end());
}