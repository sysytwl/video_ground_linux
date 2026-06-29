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
#include "hud_overlay.h"

extern HUDOverlay hud;

osd_data_t g_osd = {0};

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
        // 校验失败，丢弃
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

    case MSP_DISPLAYPORT:{
        // 数据格式：[子命令][数据...]
        if (parser->expected_len < 1) return;
        uint8_t subcmd = parser->in_buf[0];
        switch (subcmd) {
        case MSP_DP_WRITE_STRING: {
            // 格式：[row] [col] [attr] [string...] （无长度，string 后无 NULL，但包长度确定）
            if (parser->expected_len < 4) break;
            uint8_t row = parser->in_buf[1];
            uint8_t col = parser->in_buf[2];
            uint8_t attr = parser->in_buf[3];
            size_t str_len = parser->expected_len - 4;
            if (str_len > 0) {
                g_osd_screen.writeString(row, col, attr, &parser->in_buf[4], str_len);
            }
            hud.invalidateOSDTexture();
            break;
        }
        case MSP_DP_CLEAR_SCREEN:
            g_osd_screen.clear();
            hud.invalidateOSDTexture();
            break;
        case MSP_DP_HEARTBEAT:
            // 心跳，可忽略或用于重置超时
            break;
        // 可扩展其他子命令...
        default:
            break;
        }

        break;
    }
    default:
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
            parser->cmd = c;
            parser->checksum = c;  // 开始累加校验和
            parser->state = MSP_STATE_V1_LEN;
            break;
        case MSP_STATE_V1_LEN:
            parser->expected_len = c;
            parser->checksum ^= c;
            parser->buf_len = 0;
            if (c == 0) {
                // 无数据，直接跳转到校验和
                parser->state = MSP_STATE_V1_CHECKSUM;
            } else {
                parser->state = MSP_STATE_V1_DATA;
            }
            break;
        case MSP_STATE_V1_DATA:
            parser->in_buf[parser->buf_len++] = c;
            parser->checksum ^= c;
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

static std::thread msp_thread;
static std::atomic<bool> msp_thread_running{false};

static void msp_thread_func(const char *device) {
    msp_parser_t parser;
    msp_parser_init(&parser);

    int fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        perror("open msp device");
        return;
    }

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
    while (msp_thread_running) {
        ssize_t n = read(fd, buf, BUFSZ);
        if (n > 0) {
            msp_parse_bytes(&parser, buf, (size_t)n, nullptr, nullptr);
        } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
            break;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    close(fd);
}

bool msp_start() {
    if (msp_thread_running) return true;
    const char* dev = std::getenv("MSP_DEVICE");
    const char* candidates[] = {dev ? dev : "", "/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyUSB1"};
    for (const char* device : candidates) {
        if (device == nullptr || *device == '\0') continue;
        msp_thread_running = true;
        msp_thread = std::thread(msp_thread_func, device);
        return true;
    }
    return false;
}

void msp_stop() {
    if (!msp_thread_running) return;
    msp_thread_running = false;
    if (msp_thread.joinable()) msp_thread.join();
}
