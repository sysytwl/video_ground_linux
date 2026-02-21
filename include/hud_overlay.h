#ifndef HUD_OVERLAY_H
#define HUD_OVERLAY_H

#include <SDL.h>
#include <SDL_ttf.h>
#include <SDL2_gfxPrimitives.h>
#include <string>
#include <vector>
#include <SDL_image.h>
#include "msp.h"

struct HUDConfig {
    bool show_speed = true;
    bool show_altitude = true;
    bool show_heading = true;
    bool show_attitude = true;
    bool show_ground = true;
    bool show_predicted = true;
    bool show_air_ground_line = true;
    bool show_object_labels = true;
};

class HUDOverlay {
public:
    HUDOverlay(SDL_Renderer* renderer, TTF_Font* font);
    ~HUDOverlay();

    void setConfig(const HUDConfig& cfg) { config_ = cfg; }
    void updateFlightData(float speed, float altitude, float heading,
                          float pitch, float roll,
                          float predicted_speed, float predicted_altitude,
                          float predicted_heading);
    void render(int screen_w, int screen_h);
    void setRenderMode(int mode) { render_mode_ = mode; }
    void setTextLines(const std::vector<std::string>& lines) { text_lines_ = lines; }
    void renderOSD(const OSDScreen& screen, int screen_w, int screen_h);
private:
    void drawSpeedTape(int x, int y, int w, int h);
    void drawAltitudeTape(int x, int y, int w, int h);
    void drawHeadingTape(int x, int y, int w, int h);
    void drawAttitudeIndicator(int cx, int cy, int size);

    SDL_Renderer* renderer_;
    TTF_Font* font_;
    HUDConfig config_;

    int render_mode_ = 0;  // 0: graphic, 1: text
    std::vector<std::string> text_lines_;
    float speed_, altitude_, heading_;
    float pitch_, roll_;
    float pred_speed_, pred_alt_, pred_heading_;

    SDL_Texture* osd_font_atlas_ = nullptr;
    int osd_tile_w_ = 12;          // original tile width
    int osd_tile_h_ = 18;          // original tile height
    int osd_scale_ = 2;            // scaling factor for rendering
    Uint32 last_blink_time_ = 0;
    bool blink_on_ = true;

    SDL_Color getColorForAttr(uint8_t attr);
    bool isBlinking(uint8_t attr);
};

#endif