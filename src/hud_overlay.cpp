#include "hud_overlay.h"
#include <SDL2_gfxPrimitives.h>
#include <cmath>
#include <sstream>
#include <algorithm>
#include "msp.h"

MenuItem menu_items_[] = {
    [display_mode] = {
        .name = "Display Mode",
        .options = {"Normal", "Side-by-Side"},
        .selected = 0,
        .editable = true,
    },
    [interface] = {
        .name = "Interface 1",
        .options = {"wlan0mon"},
        .selected = 0,
        .editable = true,
    },
    [interface2] = {
        .name = "Interface 2",
        .options = {"None"},
        .selected = 0,
        .editable = true,
    },
    [mac] = {
        .name = "Devices",
        .options = {"None"},
        .selected = 0,
        .editable = true,
    },
    [scan] = {
        .name = "Scan",
        .options = {"Idle", "Scan MACs"},
        .selected = 0,
        .editable = true,
    },
    [start] = {
        .name = "Control",
        .options = {"Start Capture", "Stop Capture"},
        .selected = 0,
        .editable = true,
    },
};

static Uint32 getSurfacePixel(SDL_Surface* surface, int x, int y) {
    const int bpp = surface->format->BytesPerPixel;
    const Uint8* pixel = static_cast<const Uint8*>(surface->pixels) + y * surface->pitch + x * bpp;

    switch (bpp) {
    case 1:
        return *pixel;
    case 2:
        return *reinterpret_cast<const Uint16*>(pixel);
    case 3:
        if (SDL_BYTEORDER == SDL_BIG_ENDIAN) {
            return pixel[0] << 16 | pixel[1] << 8 | pixel[2];
        }
        return pixel[0] | pixel[1] << 8 | pixel[2] << 16;
    case 4:
        return *reinterpret_cast<const Uint32*>(pixel);
    default:
        return 0;
    }
}

HUDOverlay::HUDOverlay() {
    //populate_menu();
}

HUDOverlay::~HUDOverlay() {
    if (osd_font_atlas_) SDL_DestroyTexture(osd_font_atlas_);
    if (osd_font_atlas_surf_) SDL_FreeSurface(osd_font_atlas_surf_);
}

void HUDOverlay::init(SDL_Renderer* renderer, TTF_Font* font){
    renderer_ = renderer;
    font_ = font;

    // Load the Betaflight OSD font atlas
    SDL_Surface* surface = IMG_Load("vision.png");
    if (surface) {
        const Uint32 background_key = getSurfacePixel(surface, 0, 0);
        SDL_SetColorKey(surface, SDL_TRUE, background_key);
        // keep the surface for software glyph blitting in worker thread
        osd_font_atlas_surf_ = surface;
        osd_font_atlas_ = SDL_CreateTextureFromSurface(renderer_, surface);
        if (!osd_font_atlas_) {
            SDL_Log("Failed to create texture from vision.png: %s", SDL_GetError());
        } else {
            SDL_SetTextureBlendMode(osd_font_atlas_, SDL_BLENDMODE_BLEND);
            SDL_Log("OSD font atlas loaded successfully.");
        }
    } else {
        SDL_Log("Failed to load vision.png: %s", IMG_GetError());
    }
    last_blink_time_ = SDL_GetTicks();
}

DisplayMode HUDOverlay::getDisplayMode() const {
    if (menu_items_[display_mode].selected == 1) {
        return DISPLAY_SIDE_BY_SIDE;
    }
    return DISPLAY_NORMAL;
}

void HUDOverlay::drawOSDContent(int screen_w, int screen_h) {
    if (!render_mode_logged_) {
        render_mode_logged_ = true;
        SDL_Log("HUDOverlay render mode: TEXT");
    }

    if (!osd_font_atlas_) return;

    Uint32 now = SDL_GetTicks();
    if (now - last_blink_time_ > 500) {
        blink_on_ = !blink_on_;
        last_blink_time_ = now;
    }

    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
    int rows = g_osd_screen.rows();
    int cols = g_osd_screen.cols();
    if (rows <= 0 || cols <= 0 || screen_w <= 0 || screen_h <= 0) return;

    for (int r = 0; r < rows; ++r) {
        for (int c = 0; c < cols; ++c) {
            OSDChar ch = g_osd_screen.getCharAt(r, c);
            if (ch.character == ' ' && ch.attribute == 0) continue;
            if (isBlinking(ch.attribute) && !blink_on_) continue;

            int tile_index = ch.character;
            int tile_row = tile_index / 16;
            int tile_col = tile_index % 16;
            SDL_Rect src = { tile_col * (osd_tile_w_ + 1), tile_row * (osd_tile_h_ + 1), osd_tile_w_, osd_tile_h_ };
            const int x0 = (c * screen_w) / cols;
            const int x1 = ((c + 1) * screen_w) / cols;
            const int y0 = (r * screen_h) / rows;
            const int y1 = ((r + 1) * screen_h) / rows;
            SDL_Rect dst = { x0, y0, std::max(1, x1 - x0), std::max(1, y1 - y0) };
            SDL_Color color = getColorForAttr(ch.attribute);
            SDL_SetTextureColorMod(osd_font_atlas_, color.r, color.g, color.b);
            SDL_SetTextureAlphaMod(osd_font_atlas_, color.a);
            SDL_RenderCopy(renderer_, osd_font_atlas_, &src, &dst);
        }
    }
}

void HUDOverlay::renderOSD(int screen_w, int screen_h) {
    if (!renderer_) return;
    SDL_SetRenderDrawBlendMode(renderer_, SDL_BLENDMODE_BLEND);
    drawOSDContent(screen_w, screen_h);
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

// draw the menu
void HUDOverlay::draw(int width, int height) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (!menu_visible_) return;

    int menu_w = 400;
    int menu_h = 90 + static_cast<int>(menu_items_count) * 35;
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
    menu_items_[interface].options = interfaces.empty() ? std::vector<std::string>{"None"} : interfaces;
    menu_items_[interface].selected = 0;

    menu_items_[interface2].options.clear();
    menu_items_[interface2].options.push_back("None");
    menu_items_[interface2].options.insert(menu_items_[interface2].options.end(), interfaces.begin(), interfaces.end());
    menu_items_[interface2].selected = 0;

}

void HUDOverlay::set_discovered_devices(const std::vector<DiscoveredDevice>& devices) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    discovered_devices_ = devices;
    menu_items_[mac].options.clear();
    menu_items_[mac].options.push_back("None");
    for (const auto& device : devices) {
        menu_items_[mac].options.push_back(device.mac + " CH" + std::to_string(device.channel));
    }
    menu_items_[mac].selected = 0;
}

void HUDOverlay::navigate_up() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (selected_item_ > 0) selected_item_--;
}

void HUDOverlay::navigate_down() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (selected_item_ + 1 < menu_items_count) selected_item_++;
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
    if (menu_items_[interface].options.size() > menu_items_[interface].selected)
        return menu_items_[interface].options[menu_items_[interface].selected];
    return "wlan0mon";
}

std::vector<std::string> HUDOverlay::get_selected_interfaces() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    std::vector<std::string> selected;

    auto add_interface = [&selected](const MenuItem& item) {
        if (item.options.size() <= item.selected) return;
        const std::string& value = item.options[item.selected];
        if (value.empty() || value == "None") return;
        if (std::find(selected.begin(), selected.end(), value) == selected.end()) {
            selected.push_back(value);
        }
    };

    add_interface(menu_items_[interface]);
    add_interface(menu_items_[interface2]);
    return selected;
}

DiscoveredDevice HUDOverlay::get_selected_device() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_[mac].selected == 0) return {};

    const size_t device_index = menu_items_[mac].selected - 1;
    if (discovered_devices_.size() > device_index) {
        return discovered_devices_[device_index];
    }
    return {};
}

bool HUDOverlay::should_start_capture() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
        return menu_items_[start].options[menu_items_[start].selected] == "Stop Capture";
    return false;
}

bool HUDOverlay::consume_scan_request() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_[scan].options.size() <= menu_items_[scan].selected) return false;
    if (menu_items_[scan].options[menu_items_[scan].selected] != "Scan MACs") return false;

    menu_items_[scan].selected = 0;
    return true;
}
