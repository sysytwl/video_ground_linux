// msp_osd_parser.h
#ifndef MSP_OSD_PARSER_H
#define MSP_OSD_PARSER_H

#include <stdint.h>
#include <stddef.h>

// 常用MSP指令ID（仅列出与OSD相关的部分）
#define MSP_ATTITUDE        108
#define MSP_ALTITUDE        109
#define MSP_ANALOG          110
#define MSP_GPS             111
#define MSP_STATUS          101
#define MSP_OSD_CONFIG      89   // 获取OSD布局配置
// 可根据需要添加更多

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

#endif