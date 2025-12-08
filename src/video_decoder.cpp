#include <iostream>
#include <opencv2/opencv.hpp>
#include <opencv2/gpu/gpu.hpp>  // GPU加速
#include "video_decoder.h"

class VideoDecoder {
private:
    cv::Mat frame;
    cv::gpu::GpuMat gpu_frame;
    cv::VideoWriter writer;
    bool use_gpu;

public:
    VideoDecoder(bool gpu_accel = true) : use_gpu(gpu_accel) {
        if (use_gpu && !cv::gpu::getCudaEnabledDeviceCount()) {
            std::cerr << "GPU acceleration not supported, falling back to CPU" << std::endl;
            use_gpu = false;
        }
    }

    bool decode_jpeg(const std::vector<uint8_t>& data, cv::Mat& output) {
        try {
            cv::Mat img = cv::imdecode(cv::Mat(data), cv::IMREAD_COLOR);
            if (img.empty()) return false;

            if (use_gpu) {
                gpu_frame.upload(img);
                gpu_frame.download(output);
            } else {
                output = img;
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    void display_frame(const cv::Mat& frame, const std::vector<OSDItem>& osd_items) {
        cv::Mat display_frame = frame.clone();
        
        // 绘制OSD
        for (const auto& item : osd_items) {
            cv::putText(display_frame, item.text, 
                       cv::Point(item.x, item.y),
                       cv::FONT_HERSHEY_SIMPLEX, 0.5, 
                       cv::Scalar(0, 255, 0), 1);
        }

        cv::imshow("ESP32 Video Stream", display_frame);
        cv::waitKey(1);
    }
};