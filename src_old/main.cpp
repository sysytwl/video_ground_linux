#include <iostream>
#include <thread>
#include <mutex>
#include <queue>
#include "wifi_receiver.h"
#include "fec_decoder.h"
#include "video_decoder.h"
#include "osd_renderer.h"
#include "mavlink_handler.h"

std::mutex frame_mutex;
std::queue<cv::Mat> frame_queue;
std::queue<MAVLinkMessage> mavlink_queue;

// 处理接收到的数据包
void packet_handler(Air2Ground_Header* header, size_t size) {
    static FecDecoder fec_decoder;
    static OSRenderer osd_renderer;
    static MAVLinkHandler mav_handler;

    switch (header->type) {
        case PacketType::VIDEO: {
            std::vector<uint8_t> frame_data;
            bool complete = fec_decoder.add_block(
                header->frame_index,
                header->part_index,
                header->last_part,
                header->payload,
                size - sizeof(Air2Ground_Header),
                header->fec_k,
                header->fec_n,
                frame_data
            );

            if (complete) {
                VideoDecoder decoder;
                cv::Mat frame;
                if (decoder.decode_jpeg(frame_data, frame)) {
                    // 获取OSD数据
                    auto osd_items = osd_renderer.get_osd_items();
                    
                    // 锁定并添加到显示队列
                    std::lock_guard<std::mutex> lock(frame_mutex);
                    frame_queue.push(frame);
                }
            }
            break;
        }

        case PacketType::MAVLINK: {
            mav_handler.process_packet(header->payload, 
                                      size - sizeof(Air2Ground_Header));
            break;
        }

        default:
            std::cout << "Unknown packet type: " << (int)header->type << std::endl;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <wifi-interface>" << std::endl;
        return 1;
    }

    // ESP32的MAC地址(需要替换为实际地址)
    uint8_t esp32_mac[6] = {0x94, 0xb5, 0x55, 0x26, 0xe2, 0xfc};
    
    // 启动显示线程
    std::thread disp_thread(display_thread);
    
    // 启动WiFi接收
    WifiReceiver receiver(argv[1], esp32_mac);
    std::cout << "Starting receiver on interface " << argv[1] << std::endl;
    receiver.start(packet_handler);
    
    disp_thread.join();
    return 0;
}