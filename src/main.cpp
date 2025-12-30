#include <iostream>
#include <thread>
#include <mutex>
#include <queue>
#include <csignal>
#include <atomic>
#include "packet_sniffer.h"
#include "fec_buffer.h"
#include "fec.h"
#include "video_decoder.h"
//#include "osd_renderer.h"
//#include "mavlink_handler.h"

PacketSniffer sniffer;
ZFE_FEC fec;

// Global signal handler
std::atomic<bool> g_signal_caught(false);

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_signal_caught = true;
        std::cout << "\nSignal caught, stopping capture..." << std::endl;
        
        sniffer.stop_capture();
    }
}


std::map<std::string, std::string> args_;
void parse_args(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--mac") {
            if (i + 1 < argc && argv[i+1][0] != '-') {
                args_["mac"] = argv[++i];
                //filter_by_mac_ = true;
            }
        } else if (arg == "--interface" || arg == "-i") {
            if (i + 1 < argc) {
                args_["interface"] = argv[++i];
            }
        } else if (arg == "--count" || arg == "-c") {
            if (i + 1 < argc) {
                args_["count"] = argv[++i];
            }
        } else if (arg == "--filter" || arg == "-f") {
            if (i + 1 < argc) {
                args_["filter"] = argv[++i];
            }
        } else if (arg == "--help" || arg == "-h") {
            args_["help"] = "true";
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
        }
    }
}

void print_usage(const char* prog_name){
    std::cout << "WiFi Packet Sniffer with Radiotap Support and Multi-threading" << std::endl;
    std::cout << "Usage: sudo " << prog_name << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --mac <address>      Filter by transmitter MAC address (WiFi addr2)" << std::endl;
    std::cout << "  --mac                Capture from all MAC addresses" << std::endl;
    std::cout << "  --interface, -i <iface>  WiFi interface (default: wlan0mon)" << std::endl;
    std::cout << "  --count, -c <num>    Number of packets to capture (0 = infinite)" << std::endl;
    std::cout << "  --filter, -f <expr>  BPF filter expression" << std::endl;
    std::cout << "  --help, -h           Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "IMPORTANT: Interface must be in monitor mode!" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage Examples:" << std::endl;
    std::cout << "  sudo " << prog_name << " --mac 00:1A:2B:3C:4D:5E --log-level debug" << std::endl;
    std::cout << "  sudo " << prog_name << " --mac -i wlan0mon -c 100" << std::endl;
    std::cout << "  sudo " << prog_name << " --filter \"type mgt subtype beacon\"" << std::endl;
}

void print_banner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║                   WiFi Packet Sniffer                        ║
║           Multi-threaded with Radiotap Support               ║
║                        Version 0.6                           ║
╚══════════════════════════════════════════════════════════════╝
)" << std::endl;
}

int main(int argc, char* argv[]) {
    print_banner();

    // Set up signal handler for graceful shutdown
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::thread decoder_thread(video_decoder_loop);
    
    parse_args(argc, argv);

    if (args_.count("help")) {
        print_usage(argv[0]);
        return 0;
    }

    // Check for root/sudo
    if (geteuid() != 0) {
        std::cerr << "ERROR: This program requires root privileges for packet capture!" << std::endl;
        std::cerr << "Please run with: sudo " << argv[0] << std::endl;
        return 1;
    }

    // Get interface name
    std::string interface_ = "wlan0mon";  // Default monitor mode interface
    if (args_.count("interface")) {
        interface_ = args_["interface"];
    }
    
    // Get MAC filter
    uint8_t cases = 2;
    std::string target_mac_ = args_["mac"];
    if (args_.count("mac")) {
        if (!target_mac_.empty()) {
            cases = 1;
            target_mac_ = WiFiPacket::normalize_mac(target_mac_);
            std::cout << "Filtering by Transmitter MAC: " << target_mac_ << std::endl;
        } else {
            std::cout << "Capturing from all MAC addresses" << std::endl;
        }
    } else {
        std::cout << "No MAC filter specified, capturing from all addresses" << std::endl;
        std::cout << "Use --mac <address> to filter or --mac for all addresses" << std::endl;
    }

    if (!sniffer.initialize(interface_, cases, target_mac_)) {
        return 1;
    }
    
    int packet_count = 0;
    if (args_.count("count")) {
        packet_count = std::stoi(args_["count"]);
    }

    // Start capture //block thread
    sniffer.start_capture(packet_count);

    //video_thread.join();

    std::cout << "\n═══════════════════════════════════════════════════════════" << std::endl;
    std::cout << "Capture complete!" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;


    video_stop();
    decoder_thread.join();

    return 0;
}