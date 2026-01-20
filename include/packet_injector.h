#ifndef PACKET_INJECTOR_H
#define PACKET_INJECTOR_H

#include <pcap.h>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <string>
#include "gamepad_osd.h"

// Controller packet structure (must match air side)
#pragma pack(push, 1)
struct ControllerPacket {
    uint8_t packet_version = 0x01;
    uint8_t type = 0x02;  // Controller type
    uint16_t sequence = 0;
    uint32_t buttons_bitmask = 0;
    int16_t left_stick_x = 0;
    int16_t left_stick_y = 0;
    int16_t right_stick_x = 0;
    int16_t right_stick_y = 0;
    uint8_t reserved[16] = {0};
};
#pragma pack(pop)

class PacketInjector {
private:
    pcap_t* pcap_handle_ = nullptr;
    std::string interface_;
    std::atomic<bool> running_{false};
    std::thread injection_thread_;
    std::mutex injection_mutex_;
    
    uint16_t sequence_number_ = 0;
    std::string dest_mac_ = "ff:ff:ff:ff:ff:ff"; // Broadcast
    
    // Radiotap header template for injection
    std::vector<uint8_t> create_radiotap_header();
    std::vector<uint8_t> create_wifi_header(const std::string& dest_mac);
    
public:
    PacketInjector(const std::string& interface);
    ~PacketInjector();
    
    bool initialize();
    void start();
    void stop();
    
    void send_controller_packet(const GamepadState& state);
    void set_destination_mac(const std::string& mac);
    
private:
    void injection_loop();
    std::vector<uint8_t> create_packet(const ControllerPacket& ctrl_packet);
};

#endif // PACKET_INJECTOR_H