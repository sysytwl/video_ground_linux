#include "packet_injector.h"
#include <iostream>
#include <cstring>
#include <chrono>
#include <arpa/inet.h>

PacketInjector::PacketInjector(const std::string& interface) 
    : interface_(interface) {}

PacketInjector::~PacketInjector() {
    stop();
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
    }
}

bool PacketInjector::initialize() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open interface for injection
    pcap_handle_ = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!pcap_handle_) {
        std::cerr << "Failed to open interface for injection: " << errbuf << std::endl;
        return false;
    }
    
    // Check if interface supports injection
    if (pcap_can_set_rfmon(pcap_handle_) <= 0) {
        std::cerr << "Interface does not support monitor mode/injection" << std::endl;
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    std::cout << "Packet injector initialized on " << interface_ << std::endl;
    return true;
}

void PacketInjector::start() {
    if (running_) return;
    running_ = true;
    injection_thread_ = std::thread(&PacketInjector::injection_loop, this);
    std::cout << "Packet injection started" << std::endl;
}

void PacketInjector::stop() {
    running_ = false;
    if (injection_thread_.joinable()) {
        injection_thread_.join();
    }
}

void PacketInjector::set_destination_mac(const std::string& mac) {
    std::lock_guard<std::mutex> lock(injection_mutex_);
    dest_mac_ = mac;
}

std::vector<uint8_t> PacketInjector::create_radiotap_header() {
    // Minimal Radiotap header for injection
    std::vector<uint8_t> radiotap = {
        0x00, 0x00,             // version, pad
        0x18, 0x00,             // length (24 bytes)
        0x0f, 0x80, 0x00, 0x00, // present flags (TSFT, Flags, Rate, Channel)
        
        // TSFT (8 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        
        // Flags (1 byte)
        0x10,                   // No CRC at end
        
        // Rate (1 byte) - 54 Mbps
        0x6c,                   // 54 Mbps in 500kb/s units
        
        // Channel (4 bytes) - 5 GHz channel 36
        0x24, 0x00,             // 2412 MHz (channel 1)
        0xa0, 0x00              // 2.4 GHz, no turbo
    };
    
    return radiotap;
}

std::vector<uint8_t> PacketInjector::create_wifi_header(const std::string& dest_mac) {
    std::vector<uint8_t> wifi_header(24, 0); // Minimal 802.11 header
    
    // Frame Control
    wifi_header[0] = 0x08; // Data frame
    wifi_header[1] = 0x01; // To DS
    
    // Duration
    wifi_header[2] = 0x00;
    wifi_header[3] = 0x00;
    
    // Destination MAC (broadcast)
    // Note: You'll need to parse MAC string to bytes
    wifi_header[4] = 0xff;
    wifi_header[5] = 0xff;
    wifi_header[6] = 0xff;
    wifi_header[7] = 0xff;
    wifi_header[8] = 0xff;
    wifi_header[9] = 0xff;
    
    // Source MAC (will be set by NIC)
    for (int i = 10; i < 16; i++) {
        wifi_header[i] = 0x00;
    }
    
    // BSSID (same as source for ad-hoc)
    for (int i = 16; i < 22; i++) {
        wifi_header[i] = 0x00;
    }
    
    // Sequence control
    wifi_header[22] = (sequence_number_ >> 4) & 0xFF;
    wifi_header[23] = (sequence_number_ << 4) & 0xF0;
    
    return wifi_header;
}

std::vector<uint8_t> PacketInjector::create_packet(const ControllerPacket& ctrl_packet) {
    std::vector<uint8_t> packet;
    
    // Add Radiotap header
    auto radiotap = create_radiotap_header();
    packet.insert(packet.end(), radiotap.begin(), radiotap.end());
    
    // Add WiFi header
    auto wifi_header = create_wifi_header(dest_mac_);
    packet.insert(packet.end(), wifi_header.begin(), wifi_header.end());
    
    // Add LLC/SNAP header
    uint8_t llc_header[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00};
    packet.insert(packet.end(), llc_header, llc_header + 6);
    
    // Add custom protocol ID
    uint16_t proto_id = htons(0x8888); // Custom protocol
    packet.insert(packet.end(), (uint8_t*)&proto_id, (uint8_t*)&proto_id + 2);
    
    // Add controller packet
    packet.insert(packet.end(), (uint8_t*)&ctrl_packet, 
                  (uint8_t*)&ctrl_packet + sizeof(ControllerPacket));
    
    return packet;
}

void PacketInjector::send_controller_packet(const GamepadState& state) {
    if (!pcap_handle_ || !running_) return;
    
    std::lock_guard<std::mutex> lock(injection_mutex_);
    
    ControllerPacket ctrl_packet;
    ctrl_packet.sequence = sequence_number_++;
    ctrl_packet.buttons_bitmask = state.buttons_bitmask;
    ctrl_packet.left_stick_x = state.left_stick_x;
    ctrl_packet.left_stick_y = state.left_stick_y;
    ctrl_packet.right_stick_x = state.right_stick_x;
    ctrl_packet.right_stick_y = state.right_stick_y;
    
    auto packet = create_packet(ctrl_packet);
    
    if (pcap_inject(pcap_handle_, packet.data(), packet.size()) == -1) {
        std::cerr << "Failed to inject packet: " << pcap_geterr(pcap_handle_) << std::endl;
    }
}

void PacketInjector::injection_loop() {
    const int injection_rate_hz = 30; // Send 30 packets per second
    const auto injection_interval = std::chrono::milliseconds(1000 / injection_rate_hz);
    
    while (running_) {
        auto start_time = std::chrono::steady_clock::now();
        
        // Send keep-alive or dummy packet
        GamepadState dummy_state;
        send_controller_packet(dummy_state);
        
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed < injection_interval) {
            std::this_thread::sleep_for(injection_interval - elapsed);
        }
    }
}