// msp_osd_parser.c
#include "msp.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <algorithm>
#include <array>
#include <cstdio>
#include "hud_overlay.h"
#include "app_log.h"
#include "text_osd.h"

extern HUDOverlay hud;

osd_data_t g_osd = {0};

static bool msp_debug_enabled() {
    static int cached = -1;
    if (cached < 0) {
        const char *env = std::getenv("MSP_DEBUG");
        if (env && *env) {
            cached = (strcmp(env, "0") != 0 && strcmp(env, "false") != 0 && strcmp(env, "off") != 0) ? 1 : 0;
        } else {
            cached = 1; // enable by default so MSP issues are visible immediately
        }
    }
    return cached != 0;
}

static void msp_debug_log(const char *fmt, ...) {
    if (!msp_debug_enabled()) return;
    char message[512];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    app_log("MSP", "%s", message);
}

void msp_parser_init(msp_parser_t *parser) {
    memset(parser, 0, sizeof(msp_parser_t));
    parser->state = MSP_STATE_IDLE;
}

// 处理V1包校验和并解析数据
std::mutex g_osd_mutex;
static bool msp_displayport_supported = true;
static unsigned msp_dp_frame_count = 0;
static std::chrono::steady_clock::time_point msp_dp_fps_window_start = std::chrono::steady_clock::now();

static void note_displayport_frame() {
    msp_dp_frame_count++;
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - msp_dp_fps_window_start).count();
    if (elapsed_ms >= 2000) {
        const double fps = static_cast<double>(msp_dp_frame_count) * 1000.0 / static_cast<double>(elapsed_ms);
        msp_debug_log("DisplayPort OSD fps=%.1f", fps);
        msp_dp_frame_count = 0;
        msp_dp_fps_window_start = now;
    }
}

static void publish_msp_osd_state() {
    text_osd_render_from_msp(g_osd);
}

static void handle_v1_packet(msp_parser_t *parser, uint8_t checksum, msp_osd_callback_t cb, void *user) {
    if (parser->checksum != checksum) {
        msp_debug_log("checksum mismatch for cmd=0x%02X, dropping packet", parser->cmd);
        return;
    }
    // 调用回调，传入指令和数据
    if (cb) {
        cb(parser->cmd, parser->in_buf, parser->expected_len, user);
    }

    switch (parser->cmd) {
    case MSP_ATTITUDE:
        if (parser->expected_len >= 6) {
            std::lock_guard<std::mutex> lock(g_osd_mutex);
            g_osd.roll = (int16_t)(parser->in_buf[0] | (parser->in_buf[1] << 8));
            g_osd.pitch = (int16_t)(parser->in_buf[2] | (parser->in_buf[3] << 8));
            g_osd.yaw = (int16_t)(parser->in_buf[4] | (parser->in_buf[5] << 8));
            publish_msp_osd_state();
        }
        break;
    case MSP_ALTITUDE:
        if (parser->expected_len >= 6) {
            std::lock_guard<std::mutex> lock(g_osd_mutex);
            g_osd.altitude = (int32_t)(parser->in_buf[0] | (parser->in_buf[1] << 8) |
                                        (parser->in_buf[2] << 16) | (parser->in_buf[3] << 24));
            g_osd.vario = (int16_t)(parser->in_buf[4] | (parser->in_buf[5] << 8));
            publish_msp_osd_state();
        }
        break;
    case MSP_ANALOG:
        if (parser->expected_len >= 7) {
            std::lock_guard<std::mutex> lock(g_osd_mutex);
            g_osd.voltage = parser->in_buf[0];
            g_osd.amperage = (uint16_t)(parser->in_buf[1] | (parser->in_buf[2] << 8));
            g_osd.mAh_drawn = (uint16_t)(parser->in_buf[3] | (parser->in_buf[4] << 8));
            g_osd.rssi = (uint16_t)(parser->in_buf[5] | (parser->in_buf[6] << 8));
            publish_msp_osd_state();
        }
        break;
    case MSP_GPS:
        if (parser->expected_len >= 16) {
            std::lock_guard<std::mutex> lock(g_osd_mutex);
            g_osd.gps_fix = parser->in_buf[0];
            g_osd.gps_num_sat = parser->in_buf[1];
            g_osd.gps_lat = (int32_t)(parser->in_buf[2] | (parser->in_buf[3] << 8) |
                                       (parser->in_buf[4] << 16) | (parser->in_buf[5] << 24));
            g_osd.gps_lon = (int32_t)(parser->in_buf[6] | (parser->in_buf[7] << 8) |
                                       (parser->in_buf[8] << 16) | (parser->in_buf[9] << 24));
            g_osd.gps_alt = (uint16_t)(parser->in_buf[10] | (parser->in_buf[11] << 8));
            g_osd.gps_speed = (uint16_t)(parser->in_buf[12] | (parser->in_buf[13] << 8));
            g_osd.gps_ground_course = (uint16_t)(parser->in_buf[14] | (parser->in_buf[15] << 8));
            publish_msp_osd_state();
        }
        break;
    case MSP_STATUS:
        if (parser->expected_len >= 10) {
            std::lock_guard<std::mutex> lock(g_osd_mutex);
            g_osd.cycle_time = (uint16_t)(parser->in_buf[0] | (parser->in_buf[1] << 8));
            g_osd.i2c_errors = (uint16_t)(parser->in_buf[2] | (parser->in_buf[3] << 8));
            g_osd.sensor_status = (uint16_t)(parser->in_buf[4] | (parser->in_buf[5] << 8));
            g_osd.mode_flags = (uint32_t)(parser->in_buf[6] | (parser->in_buf[7] << 8) |
                                          (parser->in_buf[8] << 16) | (parser->in_buf[9] << 24));
            if (parser->expected_len >= 11) {
                g_osd.profile = parser->in_buf[10];
            }
            g_osd.flight_mode = static_cast<uint16_t>(g_osd.mode_flags & 0xffff);
            if (g_osd.i2c_errors > 0) {
                msp_debug_log("I2C errors reported: count=%u sensors=0x%04X modes=0x%08X", g_osd.i2c_errors, g_osd.sensor_status, g_osd.mode_flags);
            }
            publish_msp_osd_state();
        }
        break;
    case MSP_SET_OSD_CANVAS:
        // 格式：[rows] [cols]
        if (parser->expected_len >= 2) {
            g_osd_screen.setSize(parser->in_buf[0], parser->in_buf[1]);
        } else {
            msp_debug_log("malformed OSD canvas packet len=%u", parser->expected_len);
        }
        break;

    case MSP_DISPLAYPORT:{
        // 数据格式：[子命令][数据...]
        if (parser->expected_len < 1) {
            msp_displayport_supported = false;
            return;
        }
        uint8_t subcmd = parser->in_buf[0];
        //msp_displayport_supported.store(true, std::memory_order_relaxed);
        text_osd_mark_fc_supported();
        switch (subcmd) {
        case MSP_DP_WRITE_STRING: {
            // 格式：[row] [col] [attr] [string...] （无长度，string 后无 NULL，但包长度确定）
            if (parser->expected_len < 4) {
                msp_debug_log("malformed DisplayPort write len=%u", parser->expected_len);
                break;
            }
            uint8_t row = parser->in_buf[1];
            uint8_t col = parser->in_buf[2];
            uint8_t attr = parser->in_buf[3];
            size_t str_len = parser->expected_len - 4;
            if (str_len > 0) {
                g_osd_screen.writeString(row, col, attr, &parser->in_buf[4], str_len);
                //note_text_osd_update();
            }
            break;
        }
        case MSP_DP_CLEAR_SCREEN:
            g_osd_screen.clear();
            //note_text_osd_update();
            break;
        case MSP_DP_HEARTBEAT:
            break;
        case MSP_DP_DRAW_SCREEN:
            note_displayport_frame();
            break;
        // 可扩展其他子命令...
        default:
            msp_debug_log("unhandled DisplayPort subcommand 0x%02X len=%u", subcmd, parser->expected_len);
            break;
        }

        break;
    }
    default:
        msp_debug_log("unhandled MSP command 0x%02X", parser->cmd);
        break;
    }
}

// 喂入字节流
void msp_parse_bytes(msp_parser_t *parser, const uint8_t *data, size_t len,
                     msp_osd_callback_t cb, void *user) {
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        switch (parser->state) {
        case MSP_STATE_IDLE:
            if (c == '$') parser->state = MSP_STATE_HEADER_START;
            break;
        case MSP_STATE_HEADER_START:
            if (c == 'M') {
                parser->state = MSP_STATE_HEADER_M;
            } else if (c == 'X') {
                parser->state = MSP_STATE_IDLE;
            } else {
                parser->state = MSP_STATE_IDLE;
            }
            break;
        case MSP_STATE_HEADER_M:
            if (c == '<' || c == '>') {
                parser->state = MSP_STATE_V1_ID;
            } else {
                parser->state = MSP_STATE_IDLE;
            }
            break;
        case MSP_STATE_V1_ID:
            parser->expected_len = c;
            parser->checksum = c;  // start checksum from length
            parser->buf_len = 0;
            parser->state = MSP_STATE_V1_LEN;
            break;
        case MSP_STATE_V1_LEN:
            parser->cmd = c;
            parser->checksum ^= c;
            parser->buf_len = 0;
            if (parser->expected_len == 0) {
                parser->state = MSP_STATE_V1_CHECKSUM;
            } else {
                parser->state = MSP_STATE_V1_DATA;
            }
            break;
        case MSP_STATE_V1_DATA:
            parser->in_buf[parser->buf_len] = c;
            parser->checksum ^= c;
            parser->buf_len++;
            if (parser->buf_len >= parser->expected_len) {
                parser->state = MSP_STATE_V1_CHECKSUM;
            }
            break;
        case MSP_STATE_V1_CHECKSUM:
            // 此时c为校验和字节
            handle_v1_packet(parser, c, cb, user);
            parser->state = MSP_STATE_IDLE;
            break;
        default:
            parser->state = MSP_STATE_IDLE;
            break;
        }
    }
}

// msp.cpp 末尾追加

OSDScreen g_osd_screen;   // 定义全局屏幕
static std::mutex air_msp_parser_mutex;
static msp_parser_t air_msp_parser;
static std::once_flag air_msp_parser_init;

void msp_feed_rx(const uint8_t* data, size_t size) {
    std::call_once(air_msp_parser_init, [] { msp_parser_init(&air_msp_parser); });
    std::lock_guard<std::mutex> lock(air_msp_parser_mutex);
    msp_parse_bytes(&air_msp_parser, data, size, nullptr, nullptr);
}

static std::thread msp_thread;
static std::atomic<bool> msp_thread_running{false};
static std::array<std::atomic<uint16_t>, 8> msp_rc_channels = {
    1500, 1500, 1500, 1000, 1500, 1500, 1500, 1500
};
static std::mutex msp_config_mutex;
static LinkConfig msp_link_config;
static std::atomic<uint32_t> msp_config_generation{0};

void msp_set_rc_channels(const std::array<uint16_t, 8>& channels) {
    for (size_t i = 0; i < channels.size(); ++i) {
        msp_rc_channels[i].store(channels[i], std::memory_order_relaxed);
    }
}

void msp_set_link_config(const LinkConfig& config) {
    std::lock_guard<std::mutex> lock(msp_config_mutex);
    msp_link_config = config;
    msp_config_generation.fetch_add(1, std::memory_order_release);
}

static bool write_all(int fd, const uint8_t* data, size_t size) {
    size_t offset = 0;
    while (offset < size && msp_thread_running) {
        const ssize_t written = write(fd, data + offset, size - offset);
        if (written > 0) {
            offset += static_cast<size_t>(written);
            continue;
        }
        if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return offset == size;
}

static uint8_t bridge_crc8(const uint8_t* data, size_t size) {
    uint8_t crc = 0;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (uint8_t bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x80) ? static_cast<uint8_t>((crc << 1) ^ 0x07) : static_cast<uint8_t>(crc << 1);
        }
    }
    return crc;
}

static bool send_link_config(int fd, uint8_t transaction) {
    LinkConfig config;
    {
        std::lock_guard<std::mutex> lock(msp_config_mutex);
        config = msp_link_config;
    }
    std::array<uint8_t, 15> frame = {
        'V', 'G', 'C', '1', transaction,
        config.resolution, config.jpeg_quality, config.fec_k, config.fec_n,
        config.wifi_channel, config.nrf_channel,
        static_cast<uint8_t>(config.switch_delay_ms & 0xff),
        static_cast<uint8_t>(config.switch_delay_ms >> 8),
        0, '\n',
    };
    frame[13] = bridge_crc8(frame.data(), 13);
    return write_all(fd, frame.data(), frame.size());
}

static bool msp_send_request(int fd, uint8_t cmd, const uint8_t *data, size_t len) {
    if (fd < 0) return false;
    std::vector<uint8_t> packet;
    packet.reserve(6 + len);
    packet.push_back('$');
    packet.push_back('M');
    packet.push_back('<');
    packet.push_back(static_cast<uint8_t>(len));
    packet.push_back(cmd);
    for (size_t i = 0; i < len; ++i) {
        packet.push_back(data[i]);
    }

    uint8_t checksum = cmd ^ static_cast<uint8_t>(len);
    for (size_t i = 0; i < len; ++i) {
        checksum ^= data[i];
    }
    packet.push_back(checksum);

    if (!write_all(fd, packet.data(), packet.size())) {
        msp_debug_log("failed to write MSP request cmd=0x%02X size=%zu: %s", cmd, packet.size(), strerror(errno));
        return false;
    }

    return true;
}

static void msp_thread_func(const char *device) {
    msp_parser_t parser;
    msp_parser_init(&parser);

    if (access(device, F_OK | R_OK | W_OK) != 0) {
        msp_debug_log("MSP device %s is not accessible: %s", device, strerror(errno));
        msp_thread_running = false;
        return;
    }

    int fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        msp_debug_log("failed to open MSP device %s: %s", device, strerror(errno));
        perror("open msp device");
        msp_thread_running = false;
        return;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    struct termios tio;
    if (tcgetattr(fd, &tio) != 0) {
        msp_debug_log("tcgetattr failed for %s: %s", device, strerror(errno));
        perror("tcgetattr");
        close(fd);
        msp_thread_running = false;
        return;
    }
    cfmakeraw(&tio);
    cfsetispeed(&tio, B115200);
    cfsetospeed(&tio, B115200);
    tio.c_cflag |= CLOCAL | CREAD;
    tio.c_cflag &= ~CRTSCTS;
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 1;
    tcsetattr(fd, TCSANOW, &tio);
    tcflush(fd, TCIFLUSH);

    constexpr size_t BUFSZ = 512;
    uint8_t buf[BUFSZ];

    const std::array<uint8_t, 5> telemetry_poll_cmds = {
        MSP_ATTITUDE,
        MSP_ALTITUDE,
        MSP_ANALOG,
        MSP_GPS,
        MSP_STATUS,
    };
    const uint8_t request_data[] = {0};
    size_t poll_index = 0;
    auto next_poll = std::chrono::steady_clock::now();
    auto next_rc_send = std::chrono::steady_clock::now();
    uint8_t config_retries = 3;
    uint32_t sent_config_generation = 0;
    auto next_config_send = std::chrono::steady_clock::now();

    while (msp_thread_running) {
        auto now = std::chrono::steady_clock::now();
        const uint32_t current_generation = msp_config_generation.load(std::memory_order_acquire);
        if (current_generation != sent_config_generation) {
            sent_config_generation = current_generation;
            config_retries = 3;
            next_config_send = now;
        }
        if (config_retries > 0 && now >= next_config_send) {
            if (send_link_config(fd, 1)) --config_retries;
            next_config_send = now + std::chrono::milliseconds(200);
        }
        if (now >= next_rc_send) {
            std::array<uint8_t, 16> rc_payload{};
            for (size_t i = 0; i < msp_rc_channels.size(); ++i) {
                const uint16_t value = msp_rc_channels[i].load(std::memory_order_relaxed);
                rc_payload[i * 2] = static_cast<uint8_t>(value & 0xff);
                rc_payload[i * 2 + 1] = static_cast<uint8_t>(value >> 8);
            }
            if (!msp_send_request(fd, MSP_SET_RAW_RC, rc_payload.data(), rc_payload.size())) {
                msp_debug_log("failed to send MSP RC channels");
            }
            next_rc_send = now + std::chrono::milliseconds(20);
        }
        if (now >= next_poll) {
            uint8_t cmd;
            if (msp_displayport_supported) {
                cmd = MSP_DISPLAYPORT;
            } else {
                cmd = telemetry_poll_cmds[poll_index % telemetry_poll_cmds.size()];
                poll_index++;
            }
            if (!msp_send_request(fd, cmd, request_data, 0)) {
                msp_debug_log("failed to send MSP poll request cmd=0x%02X", cmd);
            }
            next_poll = now + std::chrono::milliseconds(20);
        }

        ssize_t n = read(fd, buf, BUFSZ);
        if (n > 0) {
            msp_parse_bytes(&parser, buf, (size_t)n, nullptr, nullptr);
        } else if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                msp_debug_log("read error from %s: %s", device, strerror(errno));
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    close(fd);
}

bool msp_start() {
    if (msp_thread_running) return true;
    const char* dev = std::getenv("MSP_DEVICE");
    const char* candidates[] = {dev ? dev : "", "/dev/ttyUSB0", "/dev/ttyACM1", "/dev/ttyUSB1", "/dev/ttyS0", "/dev/ttyAMA0"};
    text_osd_reset_fc_state();
    //msp_displayport_supported.store(true, std::memory_order_relaxed);
    msp_dp_frame_count = 0;
    msp_dp_fps_window_start = std::chrono::steady_clock::now();

    for (const char* device : candidates) {
        if (device == nullptr || *device == '\0') continue;
        if (access(device, F_OK) != 0) {
            continue;
        }
        msp_thread_running = true;
        msp_thread = std::thread(msp_thread_func, device);
        return true;
    }

    msp_debug_log("no MSP device candidates were available");
    return false;
}

void msp_stop() {
    if (!msp_thread_running) return;
    msp_thread_running = false;
    if (msp_thread.joinable()) msp_thread.join();
}
