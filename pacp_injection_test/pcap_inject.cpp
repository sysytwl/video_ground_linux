#include <iostream>
#include <thread>
#include <cstring>
#include <cstdlib>
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>

static pcap *handle_ = nullptr;

// Define radiotap header (minimum)
typedef struct radiotap_header {
    uint8_t  it_version;     // set to 0
    uint8_t  it_pad;
    __le16 it_len;         // entire length
    __le32 it_present;     // fields present
} __attribute__((packed)) radiotap_header_t;

// Simple IEEE 802.11 header (for management/control frames)
typedef struct ieee80211_header {
    __le16 frame_control;
    __le16 duration_id;
    uint8_t  addr1[6];  // Destination
    uint8_t  addr2[6];  // Source
    uint8_t  addr3[6];  // BSSID
    uint16_t seq_ctrl;
} __attribute__((packed)) ieee80211_header_t;

// Deauthentication frame body
typedef struct deauth_frame {
    uint16_t reason_code;
} __attribute__((packed)) deauth_frame_t;

// Beacon frame body (simplified)
typedef struct beacon_frame {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;
} __attribute__((packed)) beacon_frame_t;

// Print MAC address
void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void radiotap_add_u8(uint8_t*& dst, size_t& idx, uint8_t data)
{
    *dst++ = data;
    idx++;
}

static void radiotap_add_u16(uint8_t*& dst, size_t& idx, uint16_t data)
{
    if ((idx & 1) == 1) //not aligned, pad first
    {
        radiotap_add_u8(dst, idx, 0);
    }
    *reinterpret_cast<uint16_t*>(dst) = data;
    dst += 2;
    idx += 2;
}

constexpr uint8_t WLAN_IEEE_HEADER_GROUND2AIR[]={
  0x08, 0x01, 
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
  0x94, 0xb5, 0x55, 0x26, 0xe2, 0xfc,
  0x10, 0x86
};

// Create a simple deauthentication packet
void create_packet(std::vector<uint8_t> &packet) {
    packet.clear();

    std::vector<uint8_t> RADIOTAP_HEADER;
    RADIOTAP_HEADER.clear();
    RADIOTAP_HEADER.resize(1024);
    radiotap_header & hdr = reinterpret_cast< radiotap_header & >(*RADIOTAP_HEADER.data());
    hdr.it_version = 0;
    hdr.it_present = 0;

    auto* dst = RADIOTAP_HEADER.data() + sizeof(radiotap_header);
    size_t idx = dst - RADIOTAP_HEADER.data();

    #define IEEE80211_RADIOTAP_TX_FLAGS 15
    #define IEEE80211_RADIOTAP_F_TX_NOACK	0x0008	/* don't expect an ack */
    hdr.it_present |= (1 << IEEE80211_RADIOTAP_TX_FLAGS );
        radiotap_add_u16(dst, idx, IEEE80211_RADIOTAP_F_TX_NOACK); //used to be 0x18

	#define IEEE80211_RADIOTAP_DATA_RETRIES 17
    hdr.it_present |= (1 << IEEE80211_RADIOTAP_DATA_RETRIES);
        radiotap_add_u8(dst, idx, 0x0);

    #define IEEE80211_RADIOTAP_MCS 19
    #define IEEE80211_RADIOTAP_MCS_HAVE_MCS	0x02
    #define IEEE80211_RADIOTAP_MCS_HAVE_GI 0x04
    #define IEEE80211_RADIOTAP_MCS_HAVE_BW 0x01
    #define		IEEE80211_RADIOTAP_MCS_BW_20 0
    hdr.it_present |= (1 << IEEE80211_RADIOTAP_MCS);
        radiotap_add_u8(dst, idx, IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI ); // short gI
        radiotap_add_u8(dst, idx, IEEE80211_RADIOTAP_MCS_BW_20 );  //HT20
        radiotap_add_u8(dst, idx, 0x00);  //MCS Index 0 6.5Mbps

    //finish it
    hdr.it_len = static_cast<__le16>(idx);
    RADIOTAP_HEADER.resize(idx);

    packet.insert(packet.end(), RADIOTAP_HEADER.begin(), RADIOTAP_HEADER.end());

    // IEEE header
    packet.insert(packet.end(), WLAN_IEEE_HEADER_GROUND2AIR, WLAN_IEEE_HEADER_GROUND2AIR+24);
    // Update sequence number
    // ieee80211_header_t* wifi = (ieee80211_header_t*)(packet + 
    //     sizeof(radiotap_header_t) + 2);
    // wifi->seq_ctrl = htons((i << 4) & 0xFFF0);

    // fake payload
    packet.insert(packet.end(), WLAN_IEEE_HEADER_GROUND2AIR, WLAN_IEEE_HEADER_GROUND2AIR+24);

    // // Deauthentication frame body
    // deauth_frame_t* deauth = (deauth_frame_t*)(buffer + 
    //     sizeof(radiotap_header_t) + 2 + sizeof(ieee80211_header_t));
    // deauth->reason_code = htons(0x0007);  // Class 3 frame received from non-associated STA


}

// Inject packet using pcap
void inject_packet(pcap_t* handle, uint8_t* packet, int packet_len) {
    if (pcap_inject(handle, packet, packet_len) == 0) {
        std::cerr << "Error injecting packet: " << pcap_geterr(handle) << std::endl;
    }
}
int pack_count = 0;
// Static callback function for pcap_loop
static void pcap_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    pack_count++;
}

void injection_thread_(){
    usleep(1000000 * 5);  // 1000ms delay

    // Create packet buffer
    std::vector<uint8_t> RADIOTAP_HEADER;
    std::vector<uint8_t> packet;

    for (int i = 0; i < 10000; i++) {
        create_packet(packet);

        std::cout << "\n[" << i + 1 << "] ";
        inject_packet(handle_, packet.data(), packet.size());

        usleep(10000);  // 100ms delay
    }

    pcap_breakloop(handle_);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <interface> [pcap_file]" << std::endl;
        std::cout << "Example: " << argv[0] << " mon0" << std::endl;
        //std::cout << "         " << argv[0] << " mon0 capture.pcap" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    const char* interface = argv[1];

    handle_ = pcap_create(interface, errbuf);
    if (handle_) {
        // Check if interface supports injection
        if (pcap_can_set_rfmon(handle_) <= 0) {
            std::cerr << "Interface does not support monitor mode/injection" << std::endl;
            pcap_close(handle_);
            handle_ = nullptr;
            return 1;
        }

        // if (pcap_set_rfmon(handle_, 1) != 0) {
        //     fprintf(stderr, "设置监控模式失败: %s\n", pcap_geterr(handle_));
        //     pcap_close(handle_);
        //     return 1;
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
            std::cerr << "err" << std::endl;
            return 1;
        }
    }

    if (handle_ == nullptr) {
        std::cerr << "Could not open device " << interface << ": " << errbuf << std::endl;
        std::cerr << "\nMake sure:" << std::endl;
        std::cerr << "1. Interface " << interface << " exists" << std::endl;
        std::cerr << "2. Interface is in monitor mode" << std::endl;
        std::cerr << "3. You have root privileges" << std::endl;
        
        // Try to list available devices
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == 0) {
            std::cerr << "\nAvailable interfaces:" << std::endl;
            for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
                std::cerr << "  " << d->name;
                if (d->description) {
                    std::cerr << " (" << d->description << ")";
                }
                std::cerr << std::endl;
            }
            pcap_freealldevs(alldevs);
        }
        return 1;
    }

    //injection
    std::thread injection_thread(injection_thread_);

    //blocking thread
    pcap_loop(handle_, 0, pcap_callback, nullptr);

    if (injection_thread.joinable())
        injection_thread.join();

    std::cout << "\nPACKET:"<< pack_count << std::endl;
    std::cout << "Injection complete!" << std::endl;
    
    pcap_close(handle_);
    return 0;
}