// msp_osd_parser.c
#include "msp.h"
#include <string.h>
#include <stdio.h>

osd_data_t g_osd = {0};

void msp_parser_init(msp_parser_t *parser) {
    memset(parser, 0, sizeof(msp_parser_t));
    parser->state = MSP_STATE_IDLE;
}

// 处理V1包校验和并解析数据
static void handle_v1_packet(msp_parser_t *parser, uint8_t checksum,
                             msp_osd_callback_t cb, void *user) {
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

    // 可选：将解析出的数据存入g_osd
    switch (parser->cmd) {
    case MSP_ATTITUDE:
        if (parser->expected_len >= 6) {
            g_osd.roll = (int16_t)(parser->in_buf[0] | (parser->in_buf[1] << 8));
            g_osd.pitch = (int16_t)(parser->in_buf[2] | (parser->in_buf[3] << 8));
            g_osd.yaw = (int16_t)(parser->in_buf[4] | (parser->in_buf[5] << 8));
        }
        break;
    case MSP_ALTITUDE:
        if (parser->expected_len >= 6) {
            g_osd.altitude = (int32_t)(parser->in_buf[0] | (parser->in_buf[1] << 8) |
                                        (parser->in_buf[2] << 16) | (parser->in_buf[3] << 24));
            g_osd.vario = (int16_t)(parser->in_buf[4] | (parser->in_buf[5] << 8));
        }
        break;
    case MSP_ANALOG:
        if (parser->expected_len >= 7) {
            g_osd.voltage = parser->in_buf[0];
            g_osd.amperage = (uint16_t)(parser->in_buf[1] | (parser->in_buf[2] << 8));
            g_osd.mAh_drawn = (uint16_t)(parser->in_buf[3] | (parser->in_buf[4] << 8));
            g_osd.rssi = (uint16_t)(parser->in_buf[5] | (parser->in_buf[6] << 8));
        }
        break;
    case MSP_GPS:
        if (parser->expected_len >= 16) {
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
    // 其他指令可根据需要添加
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
                parser->state = MSP_STATE_HEADER_ARROW;
            } else if (c == 'X') {
                // V2，此处简化处理，先跳过
                parser->state = MSP_STATE_IDLE; // 暂不支持V2
            } else {
                parser->state = MSP_STATE_IDLE;
            }
            break;
        case MSP_STATE_HEADER_ARROW:
            if (c == '<' || c == '>') {
                // 方向，我们只关心飞控发来的（>），但也可都接收
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