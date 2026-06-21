#ifndef HUD_OVERLAY_H
#define HUD_OVERLAY_H

#include <SDL.h>
#include <SDL_ttf.h>
#include <SDL2_gfxPrimitives.h>
#include <SDL_image.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <memory>

enum RenderMode {
    RENDER_GRAPHIC = 0,
    RENDER_TEXT = 1
};

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
    osd_mode,
    interface,
    mac,
    start,
    speed,
    alt,
    heading,
    attitude,
    predicted,
    menu_items_count
};

extern MenuItem menu_items_[];

class HUDOverlay {
public:
    HUDOverlay();
    ~HUDOverlay();

    void init(SDL_Renderer* renderer, TTF_Font* font);

    void updateFlightData(float speed, float altitude, float heading,float pitch, float roll,float predicted_speed, float predicted_altitude,float predicted_heading);
    void render(int screen_w, int screen_h);
    void setRenderMode(int mode) { menu_items_[osd_mode].selected = mode; invalidateOSDTexture(); }
    void setTextLines(const std::vector<std::string>& lines) { text_lines_ = lines; invalidateOSDTexture(); }
    DisplayMode getDisplayMode() const;

    void draw(int width, int height);
    void set_available_interfaces(const std::vector<std::string>& interfaces);
    void set_discovered_macs(const std::vector<std::string>& macs);

    void navigate_up();
    void navigate_down();
    void navigate_left();
    void navigate_right();
    void toggle_menu();
    RenderMode getRenderMode() const;

    std::string get_selected_interface() const;
    std::string get_selected_mac() const;
    bool should_start_capture() const;

private:
    void drawSpeedTape(int x, int y, int w, int h);
    void drawAltitudeTape(int x, int y, int w, int h);
    void drawHeadingTape(int x, int y, int w, int h);
    void drawAttitudeIndicator(int cx, int cy, int size);

    SDL_Renderer* renderer_;
    TTF_Font* font_;

    std::vector<std::string> text_lines_;
    float speed_, altitude_, heading_;
    float pitch_, roll_;
    float pred_speed_, pred_alt_, pred_heading_;

    SDL_Texture* osd_font_atlas_ = nullptr;
    SDL_Texture* osd_texture_ = nullptr;
    bool osd_texture_dirty_ = true;
    int osd_texture_w_ = 0;
    int osd_texture_h_ = 0;
    int render_mode_ = RENDER_GRAPHIC;

    int osd_tile_w_ = 12;          // original tile width
    int osd_tile_h_ = 18;          // original tile height
    int osd_scale_ = 2;            // scaling factor for rendering
    Uint32 last_blink_time_ = 0;
    bool blink_on_ = true;

    SDL_Color getColorForAttr(uint8_t attr);
    bool isBlinking(uint8_t attr);
    void invalidateOSDTexture();
    void ensureOSDTexture(int screen_w, int screen_h);
    void renderOSDToTexture(int screen_w, int screen_h);
    void destroyOSDTexture();

    size_t selected_item_ = 0;
    bool menu_visible_ = true;
    mutable std::mutex menu_mutex_;

    std::vector<std::string> available_interfaces_;
    std::vector<std::string> discovered_macs_;

    void populate_menu();
    void handle_toggle(MenuItem& item);
};

#endif