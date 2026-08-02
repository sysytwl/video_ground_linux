#include "text_osd.h"

#include <atomic>
#include <cstdio>
#include <cstring>

enum TextOsdElement {
    TEXT_OSD_BATTERY,
    TEXT_OSD_ARM_STATE,
    TEXT_OSD_FLYMODE,
    TEXT_OSD_WARNINGS,
    TEXT_OSD_HORIZON,
    TEXT_OSD_CROSSHAIRS,
    TEXT_OSD_CURRENT_DRAW,
    TEXT_OSD_MAH_DRAWN,
    TEXT_OSD_RSSI_VALUE,
    TEXT_OSD_ALTITUDE,
    TEXT_OSD_GPS_SPEED,
    TEXT_OSD_GPS_SATS,
    TEXT_OSD_NUMERICAL_HEADING,
    TEXT_OSD_NUMERICAL_VARIO,
    TEXT_OSD_ROLL_ANGLE,
    TEXT_OSD_PITCH_ANGLE,
    TEXT_OSD_TIMER,
    TEXT_OSD_ITEM_COUNT
};

struct TextOsdElementConfig {
    uint8_t row;
    uint8_t col;
    bool visible;
};

static std::atomic<bool> g_fc_text_osd_seen{false};

static TextOsdElementConfig g_element_config[TEXT_OSD_ITEM_COUNT] = {
    [TEXT_OSD_BATTERY]            = {1, 1, true},
    [TEXT_OSD_ARM_STATE]          = {0, 22, true},
    [TEXT_OSD_FLYMODE]            = {1, 20, true},
    [TEXT_OSD_WARNINGS]           = {13, 9, true},
    [TEXT_OSD_HORIZON]            = {7, 10, true},
    [TEXT_OSD_CROSSHAIRS]         = {7, 14, true},
    [TEXT_OSD_CURRENT_DRAW]       = {2, 1, true},
    [TEXT_OSD_MAH_DRAWN]          = {3, 1, true},
    [TEXT_OSD_RSSI_VALUE]         = {3, 11, true},
    [TEXT_OSD_ALTITUDE]           = {5, 1, true},
    [TEXT_OSD_GPS_SPEED]          = {6, 1, true},
    [TEXT_OSD_GPS_SATS]           = {7, 1, true},
    [TEXT_OSD_NUMERICAL_HEADING]  = {6, 20, true},
    [TEXT_OSD_NUMERICAL_VARIO]    = {5, 20, true},
    [TEXT_OSD_ROLL_ANGLE]         = {14, 1, true},
    [TEXT_OSD_PITCH_ANGLE]        = {14, 13, true},
    [TEXT_OSD_TIMER]              = {0, 1, true},
};

static const TextOsdElement g_display_order[] = {
    TEXT_OSD_TIMER,
    TEXT_OSD_ARM_STATE,
    TEXT_OSD_BATTERY,
    TEXT_OSD_FLYMODE,
    TEXT_OSD_CURRENT_DRAW,
    TEXT_OSD_MAH_DRAWN,
    TEXT_OSD_RSSI_VALUE,
    TEXT_OSD_ALTITUDE,
    TEXT_OSD_NUMERICAL_VARIO,
    TEXT_OSD_GPS_SPEED,
    TEXT_OSD_NUMERICAL_HEADING,
    TEXT_OSD_GPS_SATS,
    TEXT_OSD_ROLL_ANGLE,
    TEXT_OSD_PITCH_ANGLE,
    TEXT_OSD_HORIZON,
    TEXT_OSD_CROSSHAIRS,
    TEXT_OSD_WARNINGS,
};

static void write_element(TextOsdElement element, const char* text) {
    const TextOsdElementConfig& config = g_element_config[element];
    if (!config.visible || !text) return;
    g_osd_screen.writeString(config.row, config.col, 0, reinterpret_cast<const uint8_t*>(text), std::strlen(text));
}

static void format_element(TextOsdElement element, const osd_data_t& osd, char* out, size_t out_size) {
    const float voltage = static_cast<float>(osd.voltage) / 10.0f;
    const float current = static_cast<float>(osd.amperage) / 100.0f;
    const float altitude = static_cast<float>(osd.altitude) / 100.0f;
    const float speed = static_cast<float>(osd.gps_speed) * 0.036f;
    const float heading = static_cast<float>(osd.yaw) / 100.0f;
    const float roll = static_cast<float>(osd.roll) / 100.0f;
    const float pitch = static_cast<float>(osd.pitch) / 100.0f;
    const bool armed = (osd.mode_flags & 0x01u) != 0;
    const bool angle_mode = (osd.mode_flags & 0x02u) != 0;
    const bool horizon_mode = (osd.mode_flags & 0x04u) != 0;

    switch (element) {
    case TEXT_OSD_BATTERY:
        std::snprintf(out, out_size, "[BAT] %.1fV", voltage);
        break;
    case TEXT_OSD_ARM_STATE:
        std::snprintf(out, out_size, "%s", armed ? "ARMED" : "LOCKED");
        break;
    case TEXT_OSD_FLYMODE:
        if (angle_mode) {
            std::snprintf(out, out_size, "ANGL");
        } else if (horizon_mode) {
            std::snprintf(out, out_size, "HORZ");
        } else {
            std::snprintf(out, out_size, "ACRO");
        }
        break;
    case TEXT_OSD_WARNINGS:
        if (voltage > 0.0f && voltage < 10.5f) {
            std::snprintf(out, out_size, "LOW BATTERY");
        } else if (osd.i2c_errors > 0) {
            std::snprintf(out, out_size, "I2C ERR %u", osd.i2c_errors);
        } else if (!armed) {
            std::snprintf(out, out_size, "LOCKED");
        } else {
            out[0] = '\0';
        }
        break;
    case TEXT_OSD_HORIZON: {
        int offset = static_cast<int>(roll / 12.0f);
        if (offset < -3) offset = -3;
        if (offset > 3) offset = 3;
        const char* lines[] = {
            "---       ",
            " ---      ",
            "  ---     ",
            "   ---    ",
            "    ---   ",
            "     ---  ",
            "      --- "
        };
        std::snprintf(out, out_size, "%s", lines[offset + 3]);
        break;
    }
    case TEXT_OSD_CROSSHAIRS:
        std::snprintf(out, out_size, "+");
        break;
    case TEXT_OSD_CURRENT_DRAW:
        std::snprintf(out, out_size, "%.1fA", current);
        break;
    case TEXT_OSD_MAH_DRAWN:
        std::snprintf(out, out_size, "%umAh", osd.mAh_drawn);
        break;
    case TEXT_OSD_RSSI_VALUE:
        std::snprintf(out, out_size, "RSSI %u", osd.rssi);
        break;
    case TEXT_OSD_ALTITUDE:
        std::snprintf(out, out_size, "ALT %.1fm", altitude);
        break;
    case TEXT_OSD_GPS_SPEED:
        std::snprintf(out, out_size, "SPD %.1f", speed);
        break;
    case TEXT_OSD_GPS_SATS:
        std::snprintf(out, out_size, "SAT %u FIX %u", osd.gps_num_sat, osd.gps_fix);
        break;
    case TEXT_OSD_NUMERICAL_HEADING:
        std::snprintf(out, out_size, "HDG %.0f", heading);
        break;
    case TEXT_OSD_NUMERICAL_VARIO:
        std::snprintf(out, out_size, "VAR %d", osd.vario);
        break;
    case TEXT_OSD_ROLL_ANGLE:
        std::snprintf(out, out_size, "ROL %.1f", roll);
        break;
    case TEXT_OSD_PITCH_ANGLE:
        std::snprintf(out, out_size, "PIT %.1f", pitch);
        break;
    case TEXT_OSD_TIMER:
        std::snprintf(out, out_size, "TIME --:--");
        break;
    default:
        out[0] = '\0';
        break;
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
        char buffer[32];
        format_element(element, osd, buffer, sizeof(buffer));
        write_element(element, buffer);
    }
}