#include "gamepad_osd.h"
#include <iostream>
#include <algorithm>

// GamepadHandler implementation
GamepadHandler::GamepadHandler() {}

GamepadHandler::~GamepadHandler() {
    stop();
    if (js_fd_ != -1) {
        close(js_fd_);
    }
}

bool GamepadHandler::initialize(const std::string& device) {
    device_path_ = device;
    js_fd_ = open(device_path_.c_str(), O_RDONLY | O_NONBLOCK);
    if (js_fd_ == -1) {
        std::cerr << "Failed to open gamepad device: " << device_path_ << std::endl;
        return false;
    }
    
    int num_axes = 0, num_buttons = 0;
    ioctl(js_fd_, JSIOCGAXES, &num_axes);
    ioctl(js_fd_, JSIOCGBUTTONS, &num_buttons);
    
    std::cout << "Gamepad initialized: " << num_axes << " axes, " 
              << num_buttons << " buttons" << std::endl;
    return true;
}

void GamepadHandler::start() {
    if (running_) return;
    running_ = true;
    gamepad_thread_ = std::thread(&GamepadHandler::gamepad_loop, this);
}

void GamepadHandler::stop() {
    running_ = false;
    if (gamepad_thread_.joinable()) {
        gamepad_thread_.join();
    }
}

GamepadState GamepadHandler::get_state() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return current_state_;
}

void GamepadHandler::gamepad_loop() {
    js_event event;
    
    while (running_) {
        while (read(js_fd_, &event, sizeof(event)) > 0) {
            process_event(event);
        }
        
        if (errno != EAGAIN) {
            break; // Real error occurred
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void GamepadHandler::process_event(const js_event& event) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    switch (event.type & ~JS_EVENT_INIT) {
        case JS_EVENT_BUTTON:
            if (event.number < 16) {
                current_state_.buttons[event.number] = event.value;
            }
            break;
            
        case JS_EVENT_AXIS:
            float normalized = event.value / 32767.0f;
            
            switch (event.number) {
                case 0: current_state_.left_x = normalized; break;
                case 1: current_state_.left_y = normalized; break;
                case 2: current_state_.right_x = normalized; break;
                case 3: current_state_.right_y = normalized; break;
                case 4: // D-pad left/right
                    if (event.value < -8000) current_state_.dpad_left = true;
                    else if (event.value > 8000) current_state_.dpad_right = true;
                    else current_state_.dpad_left = current_state_.dpad_right = false;
                    break;
                case 5: // D-pad up/down
                    if (event.value < -8000) current_state_.dpad_up = true;
                    else if (event.value > 8000) current_state_.dpad_down = true;
                    else current_state_.dpad_up = current_state_.dpad_down = false;
                    break;
            }
            break;
    }
    
    // Update controller packet
    current_state_.buttons_bitmask = 0;
    for (int i = 0; i < 16; i++) {
        if (current_state_.buttons[i]) {
            current_state_.buttons_bitmask |= (1 << i);
        }
    }
    
    current_state_.left_stick_x = static_cast<int16_t>(current_state_.left_x * 32767);
    current_state_.left_stick_y = static_cast<int16_t>(current_state_.left_y * 32767);
    current_state_.right_stick_x = static_cast<int16_t>(current_state_.right_x * 32767);
    current_state_.right_stick_y = static_cast<int16_t>(current_state_.right_y * 32767);
}

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
    }
}

void OSDMenu::navigate_right() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    auto& item = menu_items_[selected_item_];
    if (item.editable && item.selected < item.options.size() - 1) {
        item.selected++;
    }
}

void OSDMenu::select_current() {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (selected_item_ == menu_items_.size() - 1) { // Start button
        // Toggle start state
        if (menu_items_[selected_item_].options[0] == "Start Capture") {
            menu_items_[selected_item_].options[0] = "Stop Capture";
        } else {
            menu_items_[selected_item_].options[0] = "Start Capture";
        }
    }
}

void OSDMenu::draw(cv::Mat& frame, int width, int height) {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    
    int menu_width = 400;
    int menu_height = 300;
    int start_x = (width - menu_width) / 2;
    int start_y = (height - menu_height) / 2;
    
    // Draw semi-transparent background
    cv::rectangle(frame, 
                  cv::Rect(start_x, start_y, menu_width, menu_height),
                  cv::Scalar(0, 0, 0, 200), -1);
    
    // Draw border
    cv::rectangle(frame,
                  cv::Rect(start_x, start_y, menu_width, menu_height),
                  cv::Scalar(255, 255, 255), 2);
    
    // Draw title
    cv::putText(frame, "WiFi Video Receiver",
                cv::Point(start_x + 20, start_y + 40),
                cv::FONT_HERSHEY_SIMPLEX, 1.0,
                cv::Scalar(0, 255, 255), 2);
    
    // Draw menu items
    int y_offset = start_y + 80;
    for (size_t i = 0; i < menu_items_.size(); i++) {
        const auto& item = menu_items_[i];
        std::string text = item.name + ": " + item.options[item.selected];
        
        cv::Scalar color = (i == selected_item_) ? 
                          cv::Scalar(0, 255, 0) : // Selected - green
                          cv::Scalar(255, 255, 255); // Normal - white
        
        // Draw selection arrow
        if (i == selected_item_) {
            cv::putText(frame, ">",
                        cv::Point(start_x + 10, y_offset),
                        cv::FONT_HERSHEY_SIMPLEX, 0.8,
                        cv::Scalar(0, 255, 0), 2);
        }
        
        cv::putText(frame, text,
                    cv::Point(start_x + 40, y_offset),
                    cv::FONT_HERSHEY_SIMPLEX, 0.7,
                    color, 2);
        
        y_offset += 40;
    }
    
    // Draw instructions
    cv::putText(frame, "Controls: D-Pad to navigate, A to select",
                cv::Point(start_x + 20, start_y + menu_height - 20),
                cv::FONT_HERSHEY_SIMPLEX, 0.6,
                cv::Scalar(200, 200, 200), 1);
}

std::string OSDMenu::get_selected_interface() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_.size() > 1 && menu_items_[1].options.size() > menu_items_[1].selected) {
        return menu_items_[1].options[menu_items_[1].selected];
    }
    return "wlan0mon";
}

std::string OSDMenu::get_selected_mac() const {
    std::lock_guard<std::mutex> lock(menu_mutex_);
    if (menu_items_.size() > 2 && menu_items_[2].options.size() > menu_items_[2].selected) {
        if (menu_items_[2].selected == 0) return ""; // "All" option
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

void OSDMenu::populate_menu() {
    menu_items_.clear();
    
    MenuItem mode_item;
    mode_item.name = "Mode";
    mode_item.options = {"Receive", "Inject"};
    mode_item.selected = 0;
    mode_item.editable = true;
    menu_items_.push_back(mode_item);
    
    MenuItem interface_item;
    interface_item.name = "Interface";
    interface_item.options = {"wlan0mon"};
    interface_item.selected = 0;
    interface_item.editable = true;
    menu_items_.push_back(interface_item);
    
    MenuItem mac_item;
    mac_item.name = "MAC Filter";
    mac_item.options = {"All"};
    mac_item.selected = 0;
    mac_item.editable = true;
    menu_items_.push_back(mac_item);
    
    MenuItem start_item;
    start_item.name = "Control";
    start_item.options = {"Start Capture"};
    start_item.selected = 0;
    start_item.editable = false;
    menu_items_.push_back(start_item);
}