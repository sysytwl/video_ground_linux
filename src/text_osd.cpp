#include "text_osd.h"

#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>

static constexpr uint8_t OSD_ATTR_NORMAL = 0;
static constexpr uint8_t OSD_ATTR_WARNING = 4;
static constexpr uint8_t OSD_ATTR_CRITICAL = 1 | 0x80;
static constexpr char SYM_VOLT = static_cast<char>(0x06);
static constexpr uint8_t SYM_AH_CENTER_LINE = 0x72;
static constexpr uint8_t SYM_AH_CENTER = 0x73;
static constexpr uint8_t SYM_AH_CENTER_LINE_RIGHT = 0x74;
static constexpr uint8_t SYM_AH_BAR9_0 = 0x80;
static constexpr uint8_t SYM_BATT_EMPTY = 0x96;
static constexpr uint8_t SYM_MAIN_BATT = 0x97;
static constexpr int AH_SYMBOL_COUNT = 9;

enum TextOsdElement {
    TEXT_OSD_BATTERY,
    TEXT_OSD_ARM_STATE,
    TEXT_OSD_FLYMODE,
    TEXT_OSD_WARNINGS,
    TEXT_OSD_HORIZON,
    TEXT_OSD_CROSSHAIRS,
    TEXT_OSD_ALTITUDE,
    TEXT_OSD_GPS_SPEED,
    TEXT_OSD_GPS_SATS,
    TEXT_OSD_NUMERICAL_HEADING,
    TEXT_OSD_TIMER,
    TEXT_OSD_ITEM_COUNT
};

struct TextOsdElementConfig {
    uint8_t row;
    uint8_t col;
    bool visible;
};

struct TextOsdDrawResult {
    char text[32];
    uint8_t attr;
};

static std::atomic<bool> g_fc_text_osd_seen{false};

static TextOsdElementConfig g_element_config[TEXT_OSD_ITEM_COUNT] = {
    [TEXT_OSD_BATTERY]            = {1, 1, true},
    [TEXT_OSD_ARM_STATE]          = {0, 23, true},
    [TEXT_OSD_FLYMODE]            = {1, 23, true},
    [TEXT_OSD_WARNINGS]           = {13, 8, true},
    [TEXT_OSD_HORIZON]            = {7, 11, true},
    [TEXT_OSD_CROSSHAIRS]         = {7, 13, true},
    [TEXT_OSD_ALTITUDE]           = {12, 1, true},
    [TEXT_OSD_GPS_SPEED]          = {12, 21, true},
    [TEXT_OSD_GPS_SATS]           = {2, 1, true},
    [TEXT_OSD_NUMERICAL_HEADING]  = {13, 22, true},
    [TEXT_OSD_TIMER]              = {0, 1, true},
};

static const TextOsdElement g_display_order[] = {
    TEXT_OSD_TIMER,
    TEXT_OSD_ARM_STATE,
    TEXT_OSD_BATTERY,
    TEXT_OSD_FLYMODE,
    TEXT_OSD_ALTITUDE,
    TEXT_OSD_GPS_SPEED,
    TEXT_OSD_NUMERICAL_HEADING,
    TEXT_OSD_GPS_SATS,
    TEXT_OSD_HORIZON,
    TEXT_OSD_CROSSHAIRS,
    TEXT_OSD_WARNINGS,
};

static void write_text(uint8_t row, uint8_t col, uint8_t attr, const char* text) {
    if (!text || text[0] == '\0') return;
    g_osd_screen.writeString(row, col, attr, reinterpret_cast<const uint8_t*>(text), std::strlen(text));
}

static void write_char(uint8_t row, uint8_t col, uint8_t attr, uint8_t ch) {
    g_osd_screen.writeString(row, col, attr, &ch, 1);
}

static void write_element(TextOsdElement element, const TextOsdDrawResult& result) {
    const TextOsdElementConfig& config = g_element_config[element];
    if (!config.visible) return;
    write_text(config.row, config.col, result.attr, result.text);
}

static uint8_t get_battery_symbol(float voltage) {
    if (voltage <= 0.0f) return SYM_MAIN_BATT;

    int cells = static_cast<int>(std::ceil(voltage / 4.35f));
    if (cells < 1) cells = 1;
    const float cell_voltage = voltage / static_cast<float>(cells);
    int level = static_cast<int>(std::lround((cell_voltage - 3.3f) * 6.0f / (4.2f - 3.3f)));
    if (level < 0) level = 0;
    if (level > 6) level = 6;
    return static_cast<uint8_t>(SYM_BATT_EMPTY - level);
}

static void format_element(TextOsdElement element, const osd_data_t& osd, TextOsdDrawResult& result) {
    const float voltage = static_cast<float>(osd.voltage) / 10.0f;
    const float altitude = static_cast<float>(osd.altitude) / 100.0f;
    const float speed = static_cast<float>(osd.gps_speed) * 0.036f;
    const float heading = static_cast<float>(osd.yaw) / 100.0f;
    const bool armed = (osd.mode_flags & 0x01u) != 0;
    const bool angle_mode = (osd.mode_flags & 0x02u) != 0;
    const bool horizon_mode = (osd.mode_flags & 0x04u) != 0;
    result.attr = OSD_ATTR_NORMAL;

    switch (element) {
    case TEXT_OSD_BATTERY:
        if (voltage > 0.0f && voltage < 10.5f) {
            result.attr = OSD_ATTR_CRITICAL;
        }
        std::snprintf(result.text, sizeof(result.text), "%c %.1f%c", get_battery_symbol(voltage), voltage, SYM_VOLT);
        break;
    case TEXT_OSD_ARM_STATE:
        result.attr = armed ? OSD_ATTR_NORMAL : OSD_ATTR_WARNING;
        std::snprintf(result.text, sizeof(result.text), "%s", armed ? "ARMED" : "LOCKED");
        break;
    case TEXT_OSD_FLYMODE:
        if (angle_mode) {
            std::snprintf(result.text, sizeof(result.text), "ANGL");
        } else if (horizon_mode) {
            std::snprintf(result.text, sizeof(result.text), "HORZ");
        } else {
            std::snprintf(result.text, sizeof(result.text), "ACRO");
        }
        break;
    case TEXT_OSD_WARNINGS:
        if (voltage > 0.0f && voltage < 10.5f) {
            result.attr = OSD_ATTR_CRITICAL;
            std::snprintf(result.text, sizeof(result.text), "LOW BATTERY");
        } else if (osd.i2c_errors > 0) {
            result.attr = OSD_ATTR_WARNING;
            std::snprintf(result.text, sizeof(result.text), "I2C ERR %u", osd.i2c_errors);
        } else if (!armed) {
            result.attr = OSD_ATTR_WARNING;
            std::snprintf(result.text, sizeof(result.text), "LOCKED");
        } else {
            result.text[0] = '\0';
        }
        break;
    case TEXT_OSD_HORIZON:
        result.text[0] = '\0';
        break;
    case TEXT_OSD_CROSSHAIRS:
        std::snprintf(result.text, sizeof(result.text), "%c%c%c", SYM_AH_CENTER_LINE, SYM_AH_CENTER, SYM_AH_CENTER_LINE_RIGHT);
        break;
    case TEXT_OSD_ALTITUDE:
        std::snprintf(result.text, sizeof(result.text), "ALT %.0fm", altitude);
        break;
    case TEXT_OSD_GPS_SPEED:
        std::snprintf(result.text, sizeof(result.text), "%.0fkmh", speed);
        break;
    case TEXT_OSD_GPS_SATS:
        std::snprintf(result.text, sizeof(result.text), "SATS %u", osd.gps_num_sat);
        break;
    case TEXT_OSD_NUMERICAL_HEADING:
        std::snprintf(result.text, sizeof(result.text), "%03.0f", heading);
        break;
    case TEXT_OSD_TIMER:
        std::snprintf(result.text, sizeof(result.text), "--:--");
        break;
    default:
        result.text[0] = '\0';
        break;
    }
}

static void draw_artificial_horizon(const osd_data_t& osd) {
    constexpr int center_col = 14;
    constexpr int center_row = 7;
    constexpr int max_pitch = 20 * 10;
    constexpr int max_roll = 40 * 10;
    int roll_angle = static_cast<int>(osd.roll);
    int pitch_angle = static_cast<int>(osd.pitch);

    if (roll_angle < -max_roll) roll_angle = -max_roll;
    if (roll_angle > max_roll) roll_angle = max_roll;
    if (pitch_angle < -max_pitch) pitch_angle = -max_pitch;
    if (pitch_angle > max_pitch) pitch_angle = max_pitch;

    pitch_angle = (pitch_angle * 25) / max_pitch;
    pitch_angle -= 4 * AH_SYMBOL_COUNT + 5;

    for (int x = -4; x <= 4; ++x) {
        const int y = ((-roll_angle * x) / 64) - pitch_angle;
        if (y < 0 || y > 9 * AH_SYMBOL_COUNT) continue;
        const int row = center_row - 4 + (y / AH_SYMBOL_COUNT);
        const int col = center_col + x;
        if (row < 0 || row >= MAX_OSD_ROWS || col < 0 || col >= MAX_OSD_COLS) continue;
        write_char(static_cast<uint8_t>(row), static_cast<uint8_t>(col), OSD_ATTR_NORMAL, static_cast<uint8_t>(SYM_AH_BAR9_0 + (y % AH_SYMBOL_COUNT)));
    }
}

void text_osd_reset_fc_state() {
    g_fc_text_osd_seen.store(false, std::memory_order_relaxed);
}

void text_osd_mark_fc_supported() {
    g_fc_text_osd_seen.store(true, std::memory_order_relaxed);
}

bool text_osd_has_fc_data() {
    return g_fc_text_osd_seen.load(std::memory_order_relaxed);
}

void text_osd_render_from_msp(const osd_data_t& osd) {
    if (text_osd_has_fc_data()) return;

    g_osd_screen.clear();
    for (TextOsdElement element : g_display_order) {
        if (element == TEXT_OSD_HORIZON) {
            draw_artificial_horizon(osd);
            continue;
        }
        TextOsdDrawResult result = {{0}, OSD_ATTR_NORMAL};
        format_element(element, osd, result);
        write_element(element, result);
    }
}