#ifndef GAMEPAD_OSD_H
#define GAMEPAD_OSD_H

#include <opencv2/opencv.hpp>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <memory>
#include <linux/input.h>
#include <linux/joystick.h>
#include <fcntl.h>
#include <unistd.h>

struct GamepadState {
    float left_x = 0.0f;
    float left_y = 0.0f;
    float right_x = 0.0f;
    float right_y = 0.0f;
    bool buttons[16] = {false};
    bool dpad_up = false;
    bool dpad_down = false;
    bool dpad_left = false;
    bool dpad_right = false;
    
    // Controller packet structure
    uint8_t packet_version = 0x01;
    uint8_t type = 0x02;  // Controller type
    uint32_t buttons_bitmask = 0;
    int16_t left_stick_x = 0;
    int16_t left_stick_y = 0;
    int16_t right_stick_x = 0;
    int16_t right_stick_y = 0;
};

class GamepadHandler {
private:
    int js_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread gamepad_thread_;
    GamepadState current_state_;
    std::mutex state_mutex_;
    std::string device_path_ = "/dev/input/js0";
    
public:
    GamepadHandler();
    ~GamepadHandler();
    
    bool initialize(const std::string& device = "/dev/input/js0");
    void start();
    void stop();
    GamepadState get_state();
    
private:
    void gamepad_loop();
    void process_event(const js_event& event);
};

class OSDMenu {
private:
    struct MenuItem {
        std::string name;
        std::vector<std::string> options;
        size_t selected = 0;
        bool editable = true;
    };
    
    std::vector<MenuItem> menu_items_;
    size_t selected_item_ = 0;
    std::mutex menu_mutex_;
    
    // Interface selection
    std::vector<std::string> available_interfaces_;
    std::vector<std::string> discovered_macs_;
    
public:
    OSDMenu();
    
    void set_available_interfaces(const std::vector<std::string>& interfaces);
    void set_discovered_macs(const std::vector<std::string>& macs);
    
    void navigate_up();
    void navigate_down();
    void navigate_left();
    void navigate_right();
    void select_current();
    
    void draw(cv::Mat& frame, int width, int height);
    
    std::string get_selected_interface() const;
    std::string get_selected_mac() const;
    bool should_start_capture() const;
    
private:
    void populate_menu();
};

#endif // GAMEPAD_OSD_H