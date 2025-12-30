#ifndef RADIOTAP_H
#define RADIOTAP_H
#include <cstddef>
#include <cstdint>

// Information structure to hold parsed data
struct RadiotapInfo {
    size_t radiotap_len = 0;
    int8_t signal_dbm = 0;
    uint8_t data_rate = 0;
    uint16_t channel_freq = 0;
    uint16_t channel_flags = 0;
    uint8_t antenna = 0;
    int8_t noise_dbm = 0;
    bool has_signal = false;
    bool has_noise = false;
    bool has_rate = false;
    bool has_channel = false;
    bool has_antenna = false;
};

size_t parse_header(const uint8_t* packet, uint32_t caplen, RadiotapInfo& info);

#endif // RADIOTAP_H