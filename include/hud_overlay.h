#ifndef HUD_OVERLAY_H
#define HUD_OVERLAY_H

#include <SDL.h>
#include <SDL_ttf.h>
#include <SDL2_gfxPrimitives.h>
#include <string>
#include <vector>

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

private:
    void drawSpeedTape(int x, int y, int w, int h);
    void drawAltitudeTape(int x, int y, int w, int h);
    void drawHeadingTape(int x, int y, int w, int h);
    void drawAttitudeIndicator(int cx, int cy, int size);
    void drawGroundBar(int x, int y, int w, int h);
    void drawPredictedValues();

    SDL_Renderer* renderer_;
    TTF_Font* font_;
    HUDConfig config_;

    float speed_, altitude_, heading_;
    float pitch_, roll_;
    float pred_speed_, pred_alt_, pred_heading_;
};

#endif