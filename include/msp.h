// msp_osd_parser.h
#ifndef MSP_OSD_PARSER_H
#define MSP_OSD_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <array>
#include <mutex>
#include <string>
extern std::mutex g_osd_mutex;

// 常用MSP指令ID（仅列出与OSD相关的部分）
#define MSP_ATTITUDE        108
#define MSP_ALTITUDE        109
#define MSP_ANALOG          110
#define MSP_GPS             111
#define MSP_STATUS          101
#define MSP_SET_RAW_RC      200
#define MSP_OSD_CONFIG      89   // 获取OSD布局配置
// msp.h (追加内容)

// MSP DisplayPort 指令
#define MSP_DISPLAYPORT         182
#define MSP_SET_OSD_CANVAS      202   // 可选，用于设置画布尺寸

// DisplayPort 子命令 (参考 betaflight/src/main/msp/msp_displayport.c)
#define MSP_DP_HEARTBEAT         0
#define MSP_DP_RELEASE           1
#define MSP_DP_CLEAR_SCREEN      2
#define MSP_DP_WRITE_STRING      3
#define MSP_DP_DRAW_SCREEN       4
#define MSP_DP_SET_OPTIONS       5

// 屏幕最大尺寸（可动态调整，这里预定义最大值）
#define MAX_OSD_ROWS 30
#define MAX_OSD_COLS 50

// 屏幕字符单元
struct OSDChar {
    uint8_t character;  // ASCII 字符
    uint8_t attribute;  // 属性（闪烁、颜色等）
};

// 屏幕缓冲区（单例模式，通过全局变量访问）
class OSDScreen {
public:
    OSDScreen() : rows_(16), cols_(30) {   // 默认 PAL 尺寸
        clear();
    }

    void setSize(uint8_t rows, uint8_t cols) {
        std::lock_guard<std::mutex> lock(mutex_);
        rows_ = (rows > 0 && rows <= MAX_OSD_ROWS) ? rows : MAX_OSD_ROWS;
        cols_ = (cols > 0 && cols <= MAX_OSD_COLS) ? cols : MAX_OSD_COLS;
        for (int r = 0; r < MAX_OSD_ROWS; ++r)
            for (int c = 0; c < MAX_OSD_COLS; ++c)
                buffer_[r][c] = {' ', 0};
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int r = 0; r < MAX_OSD_ROWS; ++r)
            for (int c = 0; c < MAX_OSD_COLS; ++c)
                buffer_[r][c] = {' ', 0};
    }

    OSDChar getCharAt(int row, int col) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (row >= 0 && row < rows_ && col >= 0 && col < cols_)
            return buffer_[row][col];
        return {' ', 0};
    }    

    // 在指定位置写入字符串（自动截断到行尾）
    void writeString(uint8_t row, uint8_t col, uint8_t attr, const uint8_t* str, size_t len) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (row >= rows_ || col >= cols_) return;
        size_t max_write = cols_ - col;
        if (len > max_write) len = max_write;
        for (size_t i = 0; i < len; ++i) {
            buffer_[row][col + i] = {str[i], attr};
        }
    }

    // 获取整行字符串（末尾空格可裁剪）
    std::string getRow(int row) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (row < 0 || row >= rows_) return "";
        std::string s;
        for (int c = 0; c < cols_; ++c) {
            s.push_back(buffer_[row][c].character);
        }
        // 去掉行尾空格（可选）
        while (!s.empty() && s.back() == ' ') s.pop_back();
        return s;
    }

    int rows() const { std::lock_guard<std::mutex> lock(mutex_); return rows_; }
    int cols() const { std::lock_guard<std::mutex> lock(mutex_); return cols_; }

private:
    mutable std::mutex mutex_;
    OSDChar buffer_[MAX_OSD_ROWS][MAX_OSD_COLS];
    uint8_t rows_, cols_;
};

// 全局屏幕对象（在 msp.cpp 中定义）
extern OSDScreen g_osd_screen;

// OSD数据结构，用于存储最新解析出的值
typedef struct {
    // 姿态
    int16_t roll;       // 0.01度
    int16_t pitch;
    int16_t yaw;
    // 高度
    int32_t altitude;   // 厘米
    int16_t vario;      // 垂直速度 cm/s
    // 模拟传感器
    uint8_t voltage;    // 电池电压 *10
    uint16_t amperage;  // 电流 *100
    uint16_t mAh_drawn;
    uint16_t rssi;
    // GPS
    uint8_t gps_fix;
    uint8_t gps_num_sat;
    int32_t gps_lat;    // 度 * 1e7
    int32_t gps_lon;
    uint16_t gps_alt;   // 米
    uint16_t gps_speed; // cm/s
    uint16_t gps_ground_course; // 度 *10
    // 其他
    uint16_t flight_mode;
    uint16_t cycle_time;
    uint16_t i2c_errors;
    uint16_t sensor_status;
    uint32_t mode_flags;
    uint8_t profile;
} osd_data_t;

// 回调函数类型，当解析到一个完整的OSD相关MSP包时被调用
typedef void (*msp_osd_callback_t)(uint8_t cmd, const uint8_t *data, size_t len, void *user);

enum states{
    MSP_STATE_IDLE,
    MSP_STATE_HEADER_START,
    MSP_STATE_HEADER_M,
    MSP_STATE_HEADER_ARROW,
    MSP_STATE_V1_ID,
    MSP_STATE_V1_LEN,
    MSP_STATE_V1_DATA,
    MSP_STATE_V1_CHECKSUM,
    MSP_STATE_V2_FLAG,
    MSP_STATE_V2_ID,
    MSP_STATE_V2_LEN,
    MSP_STATE_V2_DATA,
    MSP_STATE_V2_CRC
 };
// 解析器上下文，用于状态机
typedef struct {
    states state;
    uint8_t in_buf[256];        // 暂存一个包的数据
    uint8_t buf_len;            // 已接收字节数
    uint8_t expected_len;       // 期望的数据长度
    uint8_t cmd;                // 指令ID（V1）或V2低字节
    uint8_t cmd_high;           // V2指令高字节
    uint8_t flags;              // V2标志
    uint8_t checksum;           // V1校验和累加
    // V2 CRC暂略（可扩展）
} msp_parser_t;

// 初始化解析器
void msp_parser_init(msp_parser_t *parser);

// 喂入字节流，解析OSD数据
void msp_parse_bytes(msp_parser_t *parser, const uint8_t *data, size_t len,
                     msp_osd_callback_t cb, void *user);

// 全局OSD数据存储（可由回调更新）
extern osd_data_t g_osd;

struct LinkConfig {
    uint8_t resolution = 8;
    uint8_t jpeg_quality = 12;
    uint8_t fec_k = 4;
    uint8_t fec_n = 7;
    uint8_t wifi_channel = 13;
    uint8_t nrf_channel = 0;
    uint16_t switch_delay_ms = 500;
};

// Start/stop MSP serial reader (runs background thread). Device can be overridden
// via environment variable `MSP_DEVICE`. Returns true on success starting.
bool msp_start();
void msp_stop();
void msp_set_rc_channels(const std::array<uint16_t, 8>& channels);
void msp_set_link_config(const LinkConfig& config);
void msp_feed_rx(const uint8_t* data, size_t size);

#endif