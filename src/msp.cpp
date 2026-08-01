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
#include <algorithm>
#include <array>
#include "hud_overlay.h"

extern HUDOverlay hud;

osd_data_t g_osd = {0};

static FILE *msp_log_file = nullptr;

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

static void msp_debug_open_file() {
    if (msp_log_file) return;
    msp_log_file = std::fopen("msp.log", "w");
    if (!msp_log_file) {
        return;
    }
}

static void msp_debug_log(const char *fmt, ...) {
    if (!msp_debug_enabled()) return;
    msp_debug_open_file();
    if (!msp_log_file) return;
    va_list args;
    va_start(args, fmt);
    std::fprintf(msp_log_file, "[MSP DEBUG] ");
    std::vfprintf(msp_log_file, fmt, args);
    std::fprintf(msp_log_file, "\n");
    std::fflush(msp_log_file);
    va_end(args);
}

static bool g_text_osd_rate_initialized = false;
static std::chrono::steady_clock::time_point g_text_osd_rate_window_start;
static unsigned int g_text_osd_update_count = 0;

static void note_text_osd_update() {
    auto now = std::chrono::steady_clock::now();
    if (!g_text_osd_rate_initialized) {
        g_text_osd_rate_window_start = now;
        g_text_osd_rate_initialized = true;
        return;
    }

    ++g_text_osd_update_count;
    if (now - g_text_osd_rate_window_start >= std::chrono::seconds(1)) {
        msp_debug_log("text OSD MSP update freq=%u", g_text_osd_update_count);
        g_text_osd_update_count = 0;
        g_text_osd_rate_window_start = now;
    }
}

void msp_parser_init(msp_parser_t *parser) {
    memset(parser, 0, sizeof(msp_parser_t));
    parser->state = MSP_STATE_IDLE;
}

// 处理V1包校验和并解析数据
std::mutex g_osd_mutex;
static void handle_v1_packet(msp_parser_t *parser, uint8_t checksum, msp_osd_callback_t cb, void *user) {
    // 计算校验和：从指令开始到数据结束的XOR
    uint8_t calc = parser->cmd;
    calc ^= parser->expected_len;
    for (int i = 0; i < parser->expected_len; i++) {
        calc ^= parser->in_buf[i];
    }
    if (calc != checksum) {
        msp_debug_log("checksum mismatch for cmd=0x%02X, dropping packet", parser->cmd);
        return;
    }
    // 调用回调，传入指令和数据
    if (cb) {
        cb(parser->cmd, parser->in_buf, parser->expected_len, user);
    }

    hud.invalidateOSDTexture();

    switch (parser->cmd) {
    case MSP_ATTITUDE:
        if (parser->expected_len >= 6) {
            std::lock_guard<std::mutex> lock(g_osd_mutex);
            g_osd.roll = (int16_t)(parser->in_buf[0] | (parser->in_buf[1] << 8));
            g_osd.pitch = (int16_t)(parser->in_buf[2] | (parser->in_buf[3] << 8));
            g_osd.yaw = (int16_t)(parser->in_buf[4] | (parser->in_buf[5] << 8));
        }
        break;
    case MSP_ALTITUDE:
        if (parser->expected_len >= 6) {
            std::lock_guard<std::mutex> lock(g_osd_mutex);
            g_osd.altitude = (int32_t)(parser->in_buf[0] | (parser->in_buf[1] << 8) |
                                        (parser->in_buf[2] << 16) | (parser->in_buf[3] << 24));
            g_osd.vario = (int16_t)(parser->in_buf[4] | (parser->in_buf[5] << 8));
        }
        break;
    case MSP_ANALOG:
        if (parser->expected_len >= 7) {
            std::lock_guard<std::mutex> lock(g_osd_mutex);
            g_osd.voltage = parser->in_buf[0];
            g_osd.amperage = (uint16_t)(parser->in_buf[1] | (parser->in_buf[2] << 8));
            g_osd.mAh_drawn = (uint16_t)(parser->in_buf[3] | (parser->in_buf[4] << 8));
            g_osd.rssi = (uint16_t)(parser->in_buf[5] | (parser->in_buf[6] << 8));
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
        }
        break;
    case MSP_SET_OSD_CANVAS:
        // 格式：[rows] [cols]
        if (parser->expected_len >= 2) {
            g_osd_screen.setSize(parser->in_buf[0], parser->in_buf[1]);
        }
        hud.invalidateOSDTexture();
        break;

    case MSP_DISPLAYPORT: {
        // 数据格式：多个 [subcmd] [payload...] 可以连续出现
        if (parser->expected_len < 1) return;
        size_t offset = 0;
        bool osd_changed = false;
        while (offset < parser->expected_len) {
            uint8_t subcmd = parser->in_buf[offset++];
            size_t remaining = parser->expected_len - offset;
            switch (subcmd) {
            case MSP_DP_WRITE_STRING: {
                if (remaining < 3) {
                    offset = parser->expected_len;
                    break;
                }
                uint8_t row = parser->in_buf[offset++];
                uint8_t col = parser->in_buf[offset++];
                uint8_t attr = parser->in_buf[offset++];
                size_t str_len = parser->expected_len - offset;
                if (str_len > 0) {
                    g_osd_screen.writeString(row, col, attr, &parser->in_buf[offset], str_len);
                    note_text_osd_update();
                    osd_changed = true;
                }
                offset = parser->expected_len;
                break;
            }
            case MSP_DP_CLEAR_SCREEN:
                g_osd_screen.clear();
                note_text_osd_update();
                osd_changed = true;
                break;
            case MSP_DP_DRAW_SCREEN:
                osd_changed = true;
                break;
            case MSP_DP_SET_OPTIONS:
                break;
            case MSP_DP_HEARTBEAT:
                break;
            default:
                offset = parser->expected_len;
                break;
            }
        }
        if (osd_changed) {
            hud.invalidateOSDTexture();
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

static std::thread msp_thread;
static std::atomic<bool> msp_thread_running{false};

static bool msp_send_request(int fd, uint8_t cmd, const uint8_t *data, size_t len) {
    if (fd < 0) return false;
    std::vector<uint8_t> packet;
    packet.reserve(6 + len);
    packet.push_back('$');
    packet.push_back('M');
    packet.push_back('<');
    packet.push_back(cmd);
    packet.push_back(static_cast<uint8_t>(len));
    for (size_t i = 0; i < len; ++i) {
        packet.push_back(data[i]);
    }

    uint8_t checksum = cmd ^ static_cast<uint8_t>(len);
    for (size_t i = 0; i < len; ++i) {
        checksum ^= data[i];
    }
    packet.push_back(checksum);

    ssize_t written = write(fd, packet.data(), packet.size());
    if (written != static_cast<ssize_t>(packet.size())) {
        msp_debug_log("failed to write MSP request cmd=0x%02X written=%zd expected=%zu", cmd, written, packet.size());
        return false;
    }
    return true;
}

static void msp_thread_func(const char *device) {
    msp_parser_t parser;
    msp_parser_init(&parser);

    msp_debug_log("starting MSP reader thread for %s", device);

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
    msp_debug_log("opened MSP device %s", device);

    struct termios tio;
    if (tcgetattr(fd, &tio) != 0) {
        perror("tcgetattr");
        close(fd);
        return;
    }
    cfmakeraw(&tio);
    cfsetispeed(&tio, B115200);
    cfsetospeed(&tio, B115200);
    tio.c_cflag |= CLOCAL | CREAD;
    tio.c_cflag &= ~CRTSCTS;
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;
    tcsetattr(fd, TCSANOW, &tio);
    tcflush(fd, TCIFLUSH);

    constexpr size_t BUFSZ = 512;
    uint8_t buf[BUFSZ];

    const std::array<uint8_t, 6> poll_cmds = {
        MSP_DISPLAYPORT,
        MSP_ATTITUDE,
        MSP_ALTITUDE,
        MSP_ANALOG,
        MSP_GPS,
        MSP_STATUS,
    };
    const uint8_t request_data[] = {0};
    size_t poll_index = 0;
    auto next_poll = std::chrono::steady_clock::now();

    while (msp_thread_running) {
        auto now = std::chrono::steady_clock::now();
        if (now >= next_poll) {
            uint8_t cmd = poll_cmds[poll_index % poll_cmds.size()];
            msp_send_request(fd, cmd, request_data, 0);
            poll_index++;
            next_poll = now + std::chrono::milliseconds(60);
        }

        ssize_t n = read(fd, buf, BUFSZ);
        if (n > 0) {
            msp_parse_bytes(&parser, buf, (size_t)n, nullptr, nullptr);
        } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
            break;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    close(fd);
}

bool msp_start() {
    if (msp_thread_running) return true;
    const char* dev = std::getenv("MSP_DEVICE");
    const char* candidates[] = {dev ? dev : "", "/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyUSB1", "/dev/ttyS0", "/dev/ttyAMA0"};

    for (const char* device : candidates) {
        if (device == nullptr || *device == '\0') continue;
        if (access(device, F_OK) != 0) {
            continue;
        }
        msp_debug_log("trying MSP device %s", device);
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
