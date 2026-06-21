#include "hud_overlay.h"
#include <cmath>
#include <sstream>
#include "msp.h"

MenuItem menu_items_[] = {
    [display_mode] = {
        .name = "Display Mode",
        .options = {"Normal", "Side-by-Side"},
        .selected = 0,
        .editable = true,
    },
    [osd_mode] = {
        .name = "OSD Mode",
        .options = {"Graphic HUD", "Text OSD"},
        .selected = 0,
        .editable = true,
    },
    [interface] = {
        .name = "Interface",
        .options = {"wlan0mon"},
        .selected = 0,
        .editable = true,
    },
    [mac] = {
        .name = "MAC Filter",
        .options = {"All"},
        .selected = 0,
        .editable = true,
    },
    [start] = {
        .name = "Control",
        .options = {"Start Capture", "Stop Capture"},
        .selected = 0,
        .editable = true,
    },
    [speed] = {
        .name = "Show Speed",
        .options = {"Off", "On"},
        .selected = 0,
        .editable = true,
    },
    [alt] = {
        .name = "Show Altitude",
        .options = {"Off", "On"},
        .selected = 0,
        .editable = true,
    },
    [heading] = {
        .name = "Show Heading",
        .options = {"Off", "On"},
        .selected = 0,
        .editable = true,
    },
    [attitude] = {
        .name = "Show Attitude",
        .options = {"Off", "On"},
        .selected = 0,
        .editable = true,
    },
    [predicted] = {
        .name = "Show Predicted",
        .options = {"Off", "On"},
        .selected = 0,
        .editable = true,
    },
};

void HUDOverlay::populate_menu() {
    // Ensure menu selections are initialized and options are valid.
    menu_items_[display_mode].name = "Display Mode";
    menu_items_[display_mode].options = {"Normal", "Side-by-Side"};
    menu_items_[display_mode].selected = 0;
    menu_items_[display_mode].editable = true;

    menu_items_[osd_mode].name = "OSD Mode";
    menu_items_[osd_mode].options = {"Graphic HUD", "Text OSD"};
    menu_items_[osd_mode].selected = 0;
    menu_items_[osd_mode].editable = true;

    menu_items_[interface].name = "Interface";
    menu_items_[interface].options = {"wlan0mon"};
    menu_items_[interface].selected = 0;
    menu_items_[interface].editable = true;

    menu_items_[mac].name = "MAC Filter";
    menu_items_[mac].options = {"All"};
    menu_items_[mac].selected = 0;
    menu_items_[mac].editable = true;

    menu_items_[start].name = "Control";
    menu_items_[start].options = {"Start Capture", "Stop Capture"};
    menu_items_[start].selected = 0;
    menu_items_[start].editable = true;

    menu_items_[speed].name = "Show Speed";
    menu_items_[speed].options = {"Off", "On"};
    menu_items_[speed].selected = 0;
    menu_items_[speed].editable = true;

    menu_items_[alt].name = "Show Altitude";
    menu_items_[alt].options = {"Off", "On"};
    menu_items_[alt].selected = 0;
    menu_items_[alt].editable = true;

    menu_items_[heading].name = "Show Heading";
    menu_items_[heading].options = {"Off", "On"};
    menu_items_[heading].selected = 0;
    menu_items_[heading].editable = true;

    menu_items_[attitude].name = "Show Attitude";
    menu_items_[attitude].options = {"Off", "On"};
    menu_items_[attitude].selected = 0;
    menu_items_[attitude].editable = true;

    menu_items_[predicted].name = "Show Predicted";
    menu_items_[predicted].options = {"Off", "On"};
    menu_items_[predicted].selected = 0;
    menu_items_[predicted].editable = true;
}

HUDOverlay::HUDOverlay() {
    populate_menu();
}

HUDOverlay::~HUDOverlay() {
    if (osd_font_atlas_) SDL_DestroyTexture(osd_font_atlas_);
    destroyOSDTexture();
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
    osd_texture_dirty_ = true;
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
    invalidateOSDTexture();
}

void HUDOverlay::invalidateOSDTexture() {
    osd_texture_dirty_ = true;
}

void HUDOverlay::destroyOSDTexture() {
    if (osd_texture_) {
        SDL_DestroyTexture(osd_texture_);
        osd_texture_ = nullptr;
        osd_texture_w_ = 0;
        osd_texture_h_ = 0;
    }
}

DisplayMode HUDOverlay::getDisplayMode() const {
    if (menu_items_[display_mode].selected == 1) {
        return DISPLAY_SIDE_BY_SIDE;
    }
    return DISPLAY_NORMAL;
}

RenderMode HUDOverlay::getRenderMode() const {
    if (menu_items_[osd_mode].selected == 1) {
        return RENDER_TEXT;
    }
    return RENDER_GRAPHIC;
}

void HUDOverlay::ensureOSDTexture(int screen_w, int screen_h) {
    if (!osd_texture_dirty_ && osd_texture_) return;
    renderOSDToTexture(screen_w, screen_h);
}

void HUDOverlay::renderOSDToTexture(int screen_w, int screen_h) {
    if (!renderer_ || !osd_font_atlas_) return;
    if (osd_texture_) SDL_DestroyTexture(osd_texture_);

    osd_texture_w_ = screen_w;
    osd_texture_h_ = screen_h;
    osd_texture_ = SDL_CreateTexture(renderer_, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_TARGET, osd_texture_w_, osd_texture_h_);
    if (!osd_texture_) return;

    SDL_Texture* prev_target = SDL_GetRenderTarget(renderer_);
    SDL_SetRenderTarget(renderer_, osd_texture_);
    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
    SDL_SetRenderDrawColor(renderer_, 0, 0, 0, 0);
    SDL_RenderClear(renderer_);

    bool is_text_mode = menu_items_[osd_mode].selected == 1;
    bool is_side_by_side = menu_items_[display_mode].selected == 1;
    int osd_width = is_side_by_side ? screen_w / 2 : screen_w;

    if (is_text_mode) {
        if (!osd_font_atlas_) {
            SDL_SetRenderTarget(renderer_, prev_target);
            return;
        }
        Uint32 now = SDL_GetTicks();
        if (now - last_blink_time_ > 500) {
            blink_on_ = !blink_on_;
            last_blink_time_ = now;
        }
    }

    int dst_w = osd_tile_w_ * osd_scale_;
    int dst_h = osd_tile_h_ * osd_scale_;
    int margin = 20;
    int start_x = margin;
    int start_y = margin;
    int rows = g_osd_screen.rows();
    int cols = g_osd_screen.cols();

    if (!is_text_mode) {
        if (menu_items_[speed].selected) drawSpeedTape(50, screen_h/2 - 100, 40, 200);
        if (menu_items_[alt].selected) drawAltitudeTape(screen_w - 90, screen_h/2 - 100, 40, 200);
        if (menu_items_[heading].selected) drawHeadingTape(screen_w/2 - 150, screen_h - 60, 300, 40);
        if (menu_items_[attitude].selected) drawAttitudeIndicator(screen_w/2, screen_h/2, 150);
    } else {
        for (int r = 0; r < rows; ++r) {
            for (int c = 0; c < cols; ++c) {
                OSDChar ch = g_osd_screen.getCharAt(r, c);
                if (ch.character == ' ' && ch.attribute == 0) continue;
                if (isBlinking(ch.attribute) && !blink_on_) continue;

                int tile_index = ch.character;
                int tile_row = tile_index / 16;
                int tile_col = tile_index % 16;
                SDL_Rect src = { tile_col * (osd_tile_w_ + 1), tile_row * (osd_tile_h_ + 1), osd_tile_w_, osd_tile_h_ };
                SDL_Rect dst = { start_x + c * dst_w, start_y + r * dst_h, dst_w, dst_h };
                SDL_Color color = getColorForAttr(ch.attribute);
                SDL_SetTextureColorMod(osd_font_atlas_, color.r, color.g, color.b);
                SDL_SetTextureAlphaMod(osd_font_atlas_, color.a);
                SDL_RenderCopy(renderer_, osd_font_atlas_, &src, &dst);
            }
        }
    }

    SDL_SetRenderTarget(renderer_, prev_target);
    osd_texture_dirty_ = false;
}

void HUDOverlay::render(int screen_w, int screen_h) {
    bool side_by_side = menu_items_[display_mode].selected == 1;
    int osd_width = side_by_side ? screen_w / 2 : screen_w;

    ensureOSDTexture(osd_width, screen_h);
    if (!osd_texture_) return;

    SDL_SetTextureBlendMode(osd_texture_, SDL_BLENDMODE_BLEND);
    if (side_by_side) {
        SDL_Rect left_dst = {0, 0, osd_width, screen_h};
        SDL_Rect right_dst = {screen_w / 2, 0, osd_width, screen_h};
        SDL_RenderCopy(renderer_, osd_texture_, nullptr, &left_dst);
        SDL_RenderCopy(renderer_, osd_texture_, nullptr, &right_dst);
    } else {
        SDL_Rect dst = {0, 0, osd_width, screen_h};
        SDL_RenderCopy(renderer_, osd_texture_, nullptr, &dst);
    }
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
    boxRGBA(renderer_, start_x, start_y, start_x+menu_w, start_y+menu_h, 0,0,0,255);
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
    for (size_t i = 0; i < menu_items_count; i++) {
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
        invalidateOSDTexture();
    }
}

void HUDOverlay::navigate_right() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    auto& item = menu_items_[selected_item_];
    if (item.editable && item.selected < item.options.size() - 1) {
        item.selected++;
        invalidateOSDTexture();
    }
}

void HUDOverlay::toggle_menu() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    menu_visible_ = !menu_visible_;
}

std::string HUDOverlay::get_selected_interface() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_[interface].options.size() > menu_items_[interface].selected)
        return menu_items_[interface].options[menu_items_[interface].selected];
    return "wlan0mon";
}

std::string HUDOverlay::get_selected_mac() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_[mac].options.size() > menu_items_[mac].selected) {
        if (menu_items_[mac].selected == 0) return "";
        return menu_items_[mac].options[menu_items_[mac].selected];
    }
    return "";
}

bool HUDOverlay::should_start_capture() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
        return menu_items_[start].options[menu_items_[start].selected] == "Stop Capture";
    return false;
}
