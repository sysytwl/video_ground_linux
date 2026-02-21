#include "osd_menu.h"
#include <iostream>


// OSDMenu implementation
OSDMenu::OSDMenu() {
    populate_menu();
}

void OSDMenu::set_available_interfaces(const std::vector<std::string>& interfaces) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    available_interfaces_ = interfaces;
    if (!interfaces.empty() && menu_items_.size() > 1) {
        menu_items_[1].options = interfaces;
        menu_items_[1].selected = 0;
    }
}

void OSDMenu::set_discovered_macs(const std::vector<std::string>& macs) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    discovered_macs_ = macs;
    if (!macs.empty() && menu_items_.size() > 2) {
        std::vector<std::string> mac_options = {"All"};
        mac_options.insert(mac_options.end(), macs.begin(), macs.end());
        menu_items_[2].options = mac_options;
        menu_items_[2].selected = 0;
    }
}

void OSDMenu::navigate_up() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (selected_item_ > 0) selected_item_--;
}

void OSDMenu::navigate_down() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (selected_item_ < menu_items_.size() - 1) selected_item_++;
}

void OSDMenu::navigate_left() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    auto& item = menu_items_[selected_item_];
    if (item.editable && item.selected > 0) {
        item.selected--;
        if (item.is_toggle) handle_toggle(item);
    }
}

void OSDMenu::navigate_right() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    auto& item = menu_items_[selected_item_];
    if (item.editable && item.selected < item.options.size() - 1) {
        item.selected++;
        if (item.is_toggle) handle_toggle(item);
    }
}

void OSDMenu::select_current() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (selected_item_ == 3) { // Start/Stop
        if (menu_items_[selected_item_].options[0] == "Start Capture") {
            menu_items_[selected_item_].options[0] = "Stop Capture";
        } else {
            menu_items_[selected_item_].options[0] = "Start Capture";
        }
    }
}

void OSDMenu::toggle_menu() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    menu_visible_ = !menu_visible_;
}

#include <SDL2_gfxPrimitives.h>
void OSDMenu::draw(SDL_Renderer* renderer, int width, int height, TTF_Font* font) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (!menu_visible_) return;

    int menu_w = 400, menu_h = 300;
    int start_x = (width - menu_w) / 2;
    int start_y = (height - menu_h) / 2;

    // Background
    boxRGBA(renderer, start_x, start_y, start_x+menu_w, start_y+menu_h, 0,0,0,200);
    rectangleRGBA(renderer, start_x, start_y, start_x+menu_w, start_y+menu_h, 255,255,255,255);

    // Title
    SDL_Color white = {255,255,255,255};
    SDL_Surface* surf = TTF_RenderText_Solid(font, "WiFi Video Receiver", white);
    if (surf) {
        SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer, surf);
        SDL_Rect dst = {start_x + 20, start_y + 20, surf->w, surf->h};
        SDL_RenderCopy(renderer, tex, NULL, &dst);
        SDL_DestroyTexture(tex);
        SDL_FreeSurface(surf);
    }

    // Menu items
    int y = start_y + 70;
    for (size_t i = 0; i < menu_items_.size(); i++) {
        const auto& item = menu_items_[i];
        std::string text = item.name + ": " + item.options[item.selected];
        if (i == selected_item_) text = "> " + text;
        SDL_Color col = (i == selected_item_) ? (SDL_Color{0,255,0,255}) : white;
        surf = TTF_RenderText_Solid(font, text.c_str(), col);
        if (surf) {
            SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer, surf);
            SDL_Rect dst = {start_x + 20, y, surf->w, surf->h};
            SDL_RenderCopy(renderer, tex, NULL, &dst);
            SDL_DestroyTexture(tex);
            SDL_FreeSurface(surf);
        }
        y += 35;
    }

    // Instructions
    surf = TTF_RenderText_Solid(font, "D-Pad: navigate, A: select, B: toggle menu", white);
    if (surf) {
        SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer, surf);
        SDL_Rect dst = {start_x + 20, start_y + menu_h - 30, surf->w, surf->h};
        SDL_RenderCopy(renderer, tex, NULL, &dst);
        SDL_DestroyTexture(tex);
        SDL_FreeSurface(surf);
    }
}

std::string OSDMenu::get_selected_interface() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_.size() > 1 && menu_items_[1].options.size() > menu_items_[1].selected)
        return menu_items_[1].options[menu_items_[1].selected];
    return "wlan0mon";
}

std::string OSDMenu::get_selected_mac() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_.size() > 2 && menu_items_[2].options.size() > menu_items_[2].selected) {
        if (menu_items_[2].selected == 0) return "";
        return menu_items_[2].options[menu_items_[2].selected];
    }
    return "";
}

bool OSDMenu::should_start_capture() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_.size() > 3) {
        return menu_items_[3].options[0] == "Stop Capture";
    }
    return false;
}

HUDConfig OSDMenu::getHUDConfig() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    return hud_config_;
}

void OSDMenu::setHUDConfig(const HUDConfig& cfg) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    hud_config_ = cfg;
}

void OSDMenu::populate_menu() {
    menu_items_.clear();

    MenuItem mode;
    mode.name = "Mode";
    mode.options = {"Graphic HUD", "Text OSD"};
    mode.selected = 1;
    mode.editable = true;
    menu_items_.push_back(mode);

    MenuItem interface;
    interface.name = "Interface";
    interface.options = {"wlan0mon"};
    interface.selected = 0;
    interface.editable = true;
    menu_items_.push_back(interface);

    MenuItem mac;
    mac.name = "MAC Filter";
    mac.options = {"All"};
    mac.selected = 0;
    mac.editable = true;
    menu_items_.push_back(mac);

    MenuItem start;
    start.name = "Control";
    start.options = {"Start Capture"};
    start.selected = 0;
    start.editable = false;
    menu_items_.push_back(start);

    // Add HUD toggle items
    MenuItem speed;
    speed.name = "Show Speed";
    speed.options = {"On","Off"};
    speed.selected = hud_config_.show_speed ? 0 : 1;
    speed.editable = true;
    speed.is_toggle = true;
    menu_items_.push_back(speed);

    MenuItem alt;
    alt.name = "Show Altitude";
    alt.options = {"On","Off"};
    alt.selected = hud_config_.show_altitude ? 0 : 1;
    alt.editable = true;
    alt.is_toggle = true;
    menu_items_.push_back(alt);

    MenuItem heading;
    heading.name = "Show Heading";
    heading.options = {"On","Off"};
    heading.selected = hud_config_.show_heading ? 0 : 1;
    heading.editable = true;
    heading.is_toggle = true;
    menu_items_.push_back(heading);

    MenuItem attitude;
    attitude.name = "Show Attitude";
    attitude.options = {"On","Off"};
    attitude.selected = hud_config_.show_attitude ? 0 : 1;
    attitude.editable = true;
    attitude.is_toggle = true;
    menu_items_.push_back(attitude);

    MenuItem predicted;
    predicted.name = "Show Predicted";
    predicted.options = {"On","Off"};
    predicted.selected = hud_config_.show_predicted ? 0 : 1;
    predicted.editable = true;
    predicted.is_toggle = true;
    menu_items_.push_back(predicted);
}

RenderMode OSDMenu::getRenderMode() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_.empty()) return RENDER_GRAPHIC;
    return (RenderMode)menu_items_[0].selected;
}

void OSDMenu::handle_toggle(MenuItem& item) {
    bool on = (item.selected == 0);
    if (item.name == "Show Speed") hud_config_.show_speed = on;
    else if (item.name == "Show Altitude") hud_config_.show_altitude = on;
    else if (item.name == "Show Heading") hud_config_.show_heading = on;
    else if (item.name == "Show Attitude") hud_config_.show_attitude = on;
    else if (item.name == "Show Predicted") hud_config_.show_predicted = on;
}
