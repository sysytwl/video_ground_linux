#include "hud_overlay.h"
#include <cmath>
#include <sstream>
#include "msp.h"

HUDOverlay::HUDOverlay() {
    populate_menu();
}

HUDOverlay::~HUDOverlay() {
    if (osd_font_atlas_) SDL_DestroyTexture(osd_font_atlas_);
}

void HUDOverlay::init(SDL_Renderer* renderer, TTF_Font* font){
    renderer_ = renderer;
    font_ = font;

    // Load the Betaflight OSD font atlas
    SDL_Surface* surface = IMG_Load("betaflight.png");
    if (surface) {
        osd_font_atlas_ = SDL_CreateTextureFromSurface(renderer_, surface);
        SDL_FreeSurface(surface);
        if (!osd_font_atlas_) {
            SDL_Log("Failed to create texture from betaflight.png: %s", SDL_GetError());
        } else {
            SDL_Log("OSD font atlas loaded successfully.");
        }
    } else {
        SDL_Log("Failed to load betaflight.png: %s", IMG_GetError());
    }
    last_blink_time_ = SDL_GetTicks();
}

void HUDOverlay::updateFlightData(float speed, float altitude, float heading,
                                   float pitch, float roll,
                                   float pred_speed, float pred_alt, float pred_heading) {
    speed_ = speed;
    altitude_ = altitude;
    heading_ = heading;
    pitch_ = pitch;
    roll_ = roll;
    pred_speed_ = pred_speed;
    pred_alt_ = pred_alt;
    pred_heading_ = pred_heading;
}

void HUDOverlay::render(int screen_w, int screen_h) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   

    if (render_mode_ == 0) {
        // 图形模式
        if (menu_items_[speed].selected) drawSpeedTape(50, screen_h/2 - 100, 40, 200);
        if (menu_items_[alt].selected) drawAltitudeTape(screen_w - 90, screen_h/2 - 100, 40, 200);
        if (menu_items_[heading].selected) drawHeadingTape(screen_w/2 - 150, screen_h - 60, 300, 40);
        if (menu_items_[attitude].selected) drawAttitudeIndicator(screen_w/2, screen_h/2, 150);
    } else {

        if (!osd_font_atlas_) return;

        // Update blink state (500 ms period)
        Uint32 now = SDL_GetTicks();
        if (now - last_blink_time_ > 500) {
            blink_on_ = !blink_on_;
            last_blink_time_ = now;
        }

        // Determine character size on screen (scaled)
        int dst_w = osd_tile_w_ * osd_scale_;
        int dst_h = osd_tile_h_ * osd_scale_;

        // Starting position (e.g., top-left with margin)
        int margin = 20;
        int start_x = margin;
        int start_y = margin;

        // Iterate over all rows and columns of the screen
        int rows = g_osd_screen.rows();
        int cols = g_osd_screen.cols();
        for (int r = 0; r < rows; ++r) {
            for (int c = 0; c < cols; ++c) {
                OSDChar ch = g_osd_screen.getCharAt(r, c); // you need to add this getter in OSDScreen
                if (ch.character == ' ' && ch.attribute == 0) continue; // skip empty

                // Apply blink: if blinking and current blink off, skip
                if (isBlinking(ch.attribute) && !blink_on_) continue;

                // Compute source rectangle in atlas
                int tile_index = ch.character; // 0-255
                int tile_row = tile_index / 16;
                int tile_col = tile_index % 16;
                SDL_Rect src = {
                    tile_col * (osd_tile_w_ + 1), // +1 for the red line gap
                    tile_row * (osd_tile_h_ + 1),
                    osd_tile_w_,
                    osd_tile_h_
                };

                // Destination rectangle
                SDL_Rect dst = {
                    start_x + c * dst_w,
                    start_y + r * dst_h,
                    dst_w,
                    dst_h
                };

                // Set color modulation based on attribute
                SDL_Color color = getColorForAttr(ch.attribute);
                SDL_SetTextureColorMod(osd_font_atlas_, color.r, color.g, color.b);
                SDL_SetTextureAlphaMod(osd_font_atlas_, color.a);

                // Render the tile
                SDL_RenderCopy(renderer_, osd_font_atlas_, &src, &dst);
            }
        }

    }



    // std::lock_guard<std::mutex> lock(g_osd_mutex);
    // // 单位转换：MSP数据 → 显示单位
    // float speed = g_osd.gps_speed * 0.036f;          // cm/s -> km/h
    // float alt = g_osd.altitude / 100.0f;             // cm -> m
    // float heading = g_osd.yaw * 0.01f;                // 0.01° -> °
    // float pitch_deg = g_osd.pitch * 0.01f;
    // float roll_deg = g_osd.roll * 0.01f;
    // float pitch_rad = pitch_deg * M_PI / 180.0f;      // ° -> rad
    // float roll_rad = roll_deg * M_PI / 180.0f;

    // // 预测值（示例，可从其他来源获取）
    // float pred_speed = speed + 5;
    // float pred_alt = alt + 10;
    // float pred_heading = heading + 2;
}

void HUDOverlay::drawSpeedTape(int x, int y, int w, int h) {
    // Vertical speed tape (simplified)
    boxRGBA(renderer_, x, y, x+w, y+h, 0,0,0,128);
    rectangleRGBA(renderer_, x, y, x+w, y+h, 255,255,255,200);
    // Current speed marker
    int marker_y = y + h - (int)((speed_ / 200.0f) * h); // assume max speed 200
    lineRGBA(renderer_, x+w, marker_y, x+w+10, marker_y, 0,255,0,255);
    // Predicted speed (cyan)
    if (menu_items_[predicted].selected) {
        int pred_y = y + h - (int)((pred_speed_ / 200.0f) * h);
        lineRGBA(renderer_, x+w, pred_y, x+w+10, pred_y, 0,255,255,255);
    }
    // Text label
    std::string text = std::to_string((int)speed_) + " km/h";
    SDL_Color col = {255,255,255,255};
    SDL_Surface* surf = TTF_RenderText_Solid(font_, text.c_str(), col);
    if (surf) {
        SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer_, surf);
        SDL_Rect dst = {x-40, y-20, surf->w, surf->h};
        SDL_RenderCopy(renderer_, tex, NULL, &dst);
        SDL_DestroyTexture(tex);
        SDL_FreeSurface(surf);
    }
}

void HUDOverlay::drawAltitudeTape(int x, int y, int w, int h) {
    // Similar to speed tape
    boxRGBA(renderer_, x, y, x+w, y+h, 0,0,0,128);
    rectangleRGBA(renderer_, x, y, x+w, y+h, 255,255,255,200);
    int marker_y = y + h - (int)((altitude_ / 500.0f) * h);
    lineRGBA(renderer_, x-10, marker_y, x, marker_y, 0,255,0,255);
    if (menu_items_[predicted].selected) {
        int pred_y = y + h - (int)((pred_alt_ / 500.0f) * h);
        lineRGBA(renderer_, x-10, pred_y, x, pred_y, 0,255,255,255);
    }
}

void HUDOverlay::drawHeadingTape(int x, int y, int w, int h) {
    boxRGBA(renderer_, x, y, x+w, y+h, 0,0,0,128);
    rectangleRGBA(renderer_, x, y, x+w, y+h, 255,255,255,200);
    int marker_x = x + (int)((heading_ / 360.0f) * w);
    lineRGBA(renderer_, marker_x, y-10, marker_x, y+h+10, 0,255,0,255);
    if (menu_items_[predicted].selected) {
        int pred_x = x + (int)((pred_heading_ / 360.0f) * w);
        lineRGBA(renderer_, pred_x, y-10, pred_x, y+h+10, 0,255,255,255);
    }
}

#include <cmath> // Required for sin/cos/rad_to_deg conversion if roll is in radians
// --- Assuming angles are in Radians ---
// If your roll_/pitch_ are in degrees, convert them inside the function:
// double roll_rad = roll_ * M_PI / 180.0;
// double pitch_rad = pitch_ * M_PI / 180.0;
// Or define them as degrees if that's how they are stored.

void HUDOverlay::drawAttitudeIndicator(int cx, int cy, int size) {
    // Artificial horizon: ground and sky separated by pitch
    int horizon_y = cy + (int)(pitch_ * 2); // scale pitch
    
    // --- FPV STYLE (SIMPLIFIED) ---
    // Calculate rotation for roll
    double cos_roll = cos(roll_);
    double sin_roll = sin(roll_);
    
    // Horizon line length (half-width)
    int line_length = size;
    
    // Calculate endpoints of horizon line (rotated by roll)
    int start_x = cx + static_cast<int>(-line_length * cos_roll);
    int start_y = horizon_y + static_cast<int>(-line_length * sin_roll);
    int end_x = cx + static_cast<int>(line_length * cos_roll);
    int end_y = horizon_y + static_cast<int>(line_length * sin_roll);
    
    // Draw single yellow horizon line (no gap)
    lineRGBA(renderer_, start_x, start_y, end_x, end_y, 255, 255, 0, 255);
    
    // Draw pitch markers (vertical ticks)
    const int num_ticks = 10;
    const int tick_spacing = size / (num_ticks + 1);
    const int tick_length = 5;
    
    for (int i = 1; i <= num_ticks; ++i) {
        int y_pos = cy - i * tick_spacing;
        lineRGBA(renderer_, cx - tick_length, y_pos, cx + tick_length, y_pos, 255, 255, 255, 255);
        
        y_pos = cy + i * tick_spacing;
        lineRGBA(renderer_, cx - tick_length, y_pos, cx + tick_length, y_pos, 255, 255, 255, 255);
    }
    
    // Draw vertical pitch line (with crosshair gap)
    const int crosshair_gap = 10;
    lineRGBA(renderer_, cx, cy - size, cx, cy - crosshair_gap/2, 255, 255, 255, 255);
    lineRGBA(renderer_, cx, cy + crosshair_gap/2, cx, cy + size, 255, 255, 255, 255);
}

SDL_Color HUDOverlay::getColorForAttr(uint8_t attr) {
    // Attribute bits: bit7 = blink, bits0-5 = color index
    uint8_t color_index = attr & 0x3F;  // 0-63
    switch (color_index) {
        case 0:  return {255, 255, 255, 255}; // white
        case 1:  return {255, 0, 0, 255};     // red
        case 2:  return {0, 255, 0, 255};     // green
        case 3:  return {0, 0, 255, 255};     // blue
        case 4:  return {255, 255, 0, 255};   // yellow
        case 5:  return {0, 255, 255, 255};   // cyan
        case 6:  return {255, 0, 255, 255};   // magenta
        default: return {255, 255, 255, 255}; // fallback white
    }
}

bool HUDOverlay::isBlinking(uint8_t attr) {
    return (attr & 0x80) != 0;
}

#include <SDL2_gfxPrimitives.h>
void HUDOverlay::draw(int width, int height) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (!menu_visible_) return;

    int menu_w = 400, menu_h = 300;
    int start_x = (width - menu_w) / 2;
    int start_y = (height - menu_h) / 2;

    // Background
    boxRGBA(renderer_, start_x, start_y, start_x+menu_w, start_y+menu_h, 0,0,0,400);
    rectangleRGBA(renderer_, start_x, start_y, start_x+menu_w, start_y+menu_h, 255,255,255,255);

    // Title
    SDL_Color white = {255,255,255,255};
    SDL_Surface* surf = TTF_RenderText_Solid(font_, "WiFi Video Receiver", white);
    if (surf) {
        SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer_, surf);
        SDL_Rect dst = {start_x + 20, start_y + 20, surf->w, surf->h};
        SDL_RenderCopy(renderer_, tex, NULL, &dst);
        SDL_DestroyTexture(tex);
        SDL_FreeSurface(surf);
    }

    // Menu items
    int y = start_y + 70;
    for (size_t i = 0; i < predicted+1; i++) {
        const auto& item = menu_items_[i];
        std::string text = item.name + ": " + item.options[item.selected];
        if (i == selected_item_) text = "> " + text;
        SDL_Color col = (i == selected_item_) ? (SDL_Color{0,255,0,255}) : white;
        surf = TTF_RenderText_Solid(font_, text.c_str(), col);
        if (surf) {
            SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer_, surf);
            SDL_Rect dst = {start_x + 20, y, surf->w, surf->h};
            SDL_RenderCopy(renderer_, tex, NULL, &dst);
            SDL_DestroyTexture(tex);
            SDL_FreeSurface(surf);
        }
        y += 35;
    }
}

void HUDOverlay::set_available_interfaces(const std::vector<std::string>& interfaces) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    available_interfaces_ = interfaces;
    menu_items_[interface].options = interfaces;
    menu_items_[interface].selected = 0;

}

void HUDOverlay::set_discovered_macs(const std::vector<std::string>& macs) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    discovered_macs_ = macs;
    menu_items_[mac].options = macs;
    menu_items_[mac].selected = 0;
}

void HUDOverlay::navigate_up() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (selected_item_ > 0) selected_item_--;
}

void HUDOverlay::navigate_down() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (selected_item_ < predicted) selected_item_++;
}

void HUDOverlay::navigate_left() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    auto& item = menu_items_[selected_item_];
    if (item.editable && item.selected > 0) {
        item.selected--;
    }
}

void HUDOverlay::navigate_right() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    auto& item = menu_items_[selected_item_];
    if (item.editable && item.selected < item.options.size() - 1) {
        item.selected++;
    }
}

void HUDOverlay::toggle_menu() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    menu_visible_ = !menu_visible_;
}

std::string HUDOverlay::get_selected_interface() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_[1].options.size() > menu_items_[1].selected)
        return menu_items_[1].options[menu_items_[1].selected];
    return "wlan0mon";
}

std::string HUDOverlay::get_selected_mac() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_[2].options.size() > menu_items_[2].selected) {
        if (menu_items_[2].selected == 0) return "";
        return menu_items_[2].options[menu_items_[2].selected];
    }
    return "";
}

bool HUDOverlay::should_start_capture() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
        return menu_items_[3].options[menu_items_[3].selected] == "Stop Capture";
    return false;
}
