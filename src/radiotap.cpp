#include "radiotap.h"
#include <iostream>

struct RadiotapHeader {
    uint8_t version;      // Always 0
    uint8_t pad;
    uint16_t length;      // Entire header length
    uint32_t present_flags;  // Bitmask of fields present
};

// Radiotap field flags
enum RadiotapPresentFlags : uint32_t {
    TSFT = (1 << 0),
    FLAGS = (1 << 1),
    RATE = (1 << 2),
    CHANNEL = (1 << 3),
    FHSS = (1 << 4),
    DBM_ANTENNA_SIGNAL = (1 << 5),
    DBM_ANTENNA_NOISE = (1 << 6),
    LOCK_QUALITY = (1 << 7),
    TX_ATTENUATION = (1 << 8),
    DB_TX_ATTENUATION = (1 << 9),
    DBM_TX_POWER = (1 << 10),
    ANTENNA = (1 << 11),
    DB_ANTENNA_SIGNAL = (1 << 12),
    DB_ANTENNA_NOISE = (1 << 13),
    RX_FLAGS = (1 << 14),
    TX_FLAGS = (1 << 15),
    RTS_RETRIES = (1 << 16),
    DATA_RETRIES = (1 << 17),
    MCS = (1 << 19),
    A_MPDU = (1 << 20),
    VHT = (1 << 21),
    TIMESTAMP = (1 << 22),
    HE = (1 << 23),
    HE_MU = (1 << 24)
};

// Helper function to align offset
static inline size_t align_offset(size_t offset, size_t alignment) {
    return (offset + alignment - 1) & ~(alignment - 1);
}

size_t parse_header(const uint8_t* packet, uint32_t caplen, RadiotapInfo& info) {
    // Reset info structure
    info = RadiotapInfo{};

    const RadiotapHeader* radiotap = reinterpret_cast<const RadiotapHeader*>(packet);

    // // Check if we have the full Radiotap header
    // if (caplen < radiotap->length || radiotap->length < sizeof(RadiotapHeader)) {
    //     return 0;
    // }
    
    // info.radiotap_len = radiotap->length;
    
    // // Parse variable fields based on present_flags
    // uint32_t present = radiotap->present_flags;
    // size_t offset = sizeof(RadiotapHeader);
    
    // // Handle extended present flags (if bit 31 is set, there are more present flags)
    // while (present & (1U << 31)) {
    //     if (offset + 4 > caplen) {
    //         return 0;
    //     }
    //     present = *reinterpret_cast<const uint32_t*>(packet + offset);
    //     offset += 4;
    // }
    
    // // Now parse the actual fields in order of the bits set
    // for (uint32_t bit = 0; bit < 32; bit++) {
    //     if (!(present & (1U << bit))) {
    //         continue;
    //     }
        
    //     switch (bit) {
    //         case 0: // TSFT (8 bytes, 8-byte aligned)
    //             offset = align_offset(offset, 8);
    //             if (offset + 8 <= caplen) {
    //                 offset += 8;  // Skip timestamp
    //             }
    //             break;
                
    //         case 1: // FLAGS (1 byte, 1-byte aligned)
    //             offset = align_offset(offset, 1);
    //             if (offset + 1 <= caplen) {
    //                 offset += 1;  // Skip flags
    //             }
    //             break;
                
    //         case 2: // RATE (1 byte, 1-byte aligned)
    //             offset = align_offset(offset, 1);
    //             if (offset + 1 <= caplen) {
    //                 info.data_rate = packet[offset];
    //                 info.has_rate = true;
    //                 offset += 1;
    //             }
    //             break;
                
    //         case 3: // CHANNEL (2 bytes freq + 2 bytes flags, 2-byte aligned)
    //             offset = align_offset(offset, 2);
    //             if (offset + 4 <= caplen) {
    //                 info.channel_freq = *reinterpret_cast<const uint16_t*>(packet + offset);
    //                 info.channel_flags = *reinterpret_cast<const uint16_t*>(packet + offset + 2);
    //                 info.has_channel = true;
    //                 offset += 4;
    //             }
    //             break;
                
    //         case 5: // DBM_ANTENNA_SIGNAL (1 byte, 1-byte aligned)
    //             offset = align_offset(offset, 1);
    //             if (offset + 1 <= caplen) {
    //                 info.signal_dbm = static_cast<int8_t>(packet[offset]);
    //                 info.has_signal = true;
    //                 offset += 1;
    //             }
    //             break;
                
    //         case 6: // DBM_ANTENNA_NOISE (1 byte, 1-byte aligned)
    //             offset = align_offset(offset, 1);
    //             if (offset + 1 <= caplen) {
    //                 info.noise_dbm = static_cast<int8_t>(packet[offset]);
    //                 info.has_noise = true;
    //                 offset += 1;
    //             }
    //             break;
                
    //         case 11: // ANTENNA (1 byte, 1-byte aligned)
    //             offset = align_offset(offset, 1);
    //             if (offset + 1 <= caplen) {
    //                 info.antenna = packet[offset];
    //                 info.has_antenna = true;
    //                 offset += 1;
    //             }
    //             break;
                
    //         case 12: // DB_ANTENNA_SIGNAL (1 byte, 1-byte aligned) - signal in dB
    //             offset = align_offset(offset, 1);
    //             if (offset + 1 <= caplen && !info.has_signal) {
    //                 // Convert from dB to dBm (approximate)
    //                 info.signal_dbm = static_cast<int8_t>(packet[offset]);
    //                 info.has_signal = true;
    //                 offset += 1;
    //             } else {
    //                 offset += 1;
    //             }
    //             break;
                
    //         // Add more cases for other fields as needed
    //         default:
    //             // Unknown field - skip with proper alignment
    //             // For simplicity, we'll align to 1 byte and skip 1 byte
    //             offset = align_offset(offset, 1);
    //             offset += 1;
    //             break;
    //     }
        
    //     if (offset > caplen) {
    //         return 0;
    //     }
    // }
    
    return radiotap->length;
}
