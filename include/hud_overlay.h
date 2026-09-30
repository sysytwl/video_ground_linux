#ifndef HUD_OVERLAY_H
#define HUD_OVERLAY_H

#include <SDL.h>
#include <SDL_ttf.h>
#include <SDL2_gfxPrimitives.h>
#include <SDL_image.h>
#include <string>
#include <vector>
#include <mutex>
#include "packet_sniffer.h"
#include "msp.h"

enum DisplayMode {
    DISPLAY_NORMAL = 0,
    DISPLAY_SIDE_BY_SIDE = 1
};

struct MenuItem {
    std::string name;
    std::vector<std::string> options;
    size_t selected = 0;
    bool editable = true;
};

enum hud_overlay_menu{
    display_mode = 0,
    interface,
    interface2,
    mac,
    scan,
    resolution,
    jpeg_quality,
    fec_k,
    fec_n,
    wifi_channel,
    nrf_channel,
    apply_config,
    start,
    menu_items_count
};

extern MenuItem menu_items_[];

class HUDOverlay {
public:
    HUDOverlay();
    ~HUDOverlay();

    void init(SDL_Renderer* renderer, TTF_Font* font);

    DisplayMode getDisplayMode() const;

    // Draw decoded OSD onto the current render target.
    void renderOSD(int width, int height);
    void draw(int width, int height);
    void set_available_interfaces(const std::vector<std::string>& interfaces);
    void set_discovered_devices(const std::vector<DiscoveredDevice>& devices);

    void navigate_up();
    void navigate_down();
    void navigate_left();
    void navigate_right();
    void toggle_menu();

    std::string get_selected_interface() const;
    std::vector<std::string> get_selected_interfaces() const;
    DiscoveredDevice get_selected_device() const;
    bool should_start_capture() const;
    bool consume_scan_request();
    bool consume_config_request(LinkConfig& config);

private:
    SDL_Renderer* renderer_;
    TTF_Font* font_;

    SDL_Texture* osd_font_atlas_ = nullptr;
    SDL_Surface* osd_font_atlas_surf_ = nullptr; // keep surface for software blitting

    int osd_tile_w_ = 12;          // original tile width
    int osd_tile_h_ = 18;          // original tile height
    Uint32 last_blink_time_ = 0;
    bool blink_on_ = true;
    bool render_mode_logged_ = false;

    SDL_Color getColorForAttr(uint8_t attr);
    bool isBlinking(uint8_t attr);
    void drawOSDContent(int screen_w, int screen_h);

    size_t selected_item_ = 0;
    bool menu_visible_ = true;
    mutable std::mutex menu_mutex_;

    std::vector<std::string> available_interfaces_;
    std::vector<DiscoveredDevice> discovered_devices_;

};

#endif
