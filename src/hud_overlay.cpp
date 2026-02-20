#include "hud_overlay.h"
#include <cmath>
#include <sstream>

HUDOverlay::HUDOverlay(SDL_Renderer* renderer, TTF_Font* font)
    : renderer_(renderer), font_(font) {}

HUDOverlay::~HUDOverlay() {}

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

    // Example positions: speed left, altitude right, heading bottom, attitude center
    if (config_.show_speed) drawSpeedTape(50, screen_h/2 - 100, 40, 200);
    if (config_.show_altitude) drawAltitudeTape(screen_w - 90, screen_h/2 - 100, 40, 200);
    if (config_.show_heading) drawHeadingTape(screen_w/2 - 150, screen_h - 60, 300, 40);
    if (config_.show_attitude) drawAttitudeIndicator(screen_w/2, screen_h/2, 150);
    //if (config_.show_ground) drawGroundBar(screen_w/2 - 50, screen_h - 120, 100, 20);
}

void HUDOverlay::drawSpeedTape(int x, int y, int w, int h) {
    // Vertical speed tape (simplified)
    boxRGBA(renderer_, x, y, x+w, y+h, 0,0,0,128);
    rectangleRGBA(renderer_, x, y, x+w, y+h, 255,255,255,200);
    // Current speed marker
    int marker_y = y + h - (int)((speed_ / 200.0f) * h); // assume max speed 200
    lineRGBA(renderer_, x+w, marker_y, x+w+10, marker_y, 0,255,0,255);
    // Predicted speed (cyan)
    if (config_.show_predicted) {
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
    if (config_.show_predicted) {
        int pred_y = y + h - (int)((pred_alt_ / 500.0f) * h);
        lineRGBA(renderer_, x-10, pred_y, x, pred_y, 0,255,255,255);
    }
}

void HUDOverlay::drawHeadingTape(int x, int y, int w, int h) {
    boxRGBA(renderer_, x, y, x+w, y+h, 0,0,0,128);
    rectangleRGBA(renderer_, x, y, x+w, y+h, 255,255,255,200);
    int marker_x = x + (int)((heading_ / 360.0f) * w);
    lineRGBA(renderer_, marker_x, y-10, marker_x, y+h+10, 0,255,0,255);
    if (config_.show_predicted) {
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

void HUDOverlay::drawGroundBar(int x, int y, int w, int h) {
    // Just a simple bar
    boxRGBA(renderer_, x, y, x+w, y+h, 139,69,19,200);
    rectangleRGBA(renderer_, x, y, x+w, y+h, 255,255,255,200);
}