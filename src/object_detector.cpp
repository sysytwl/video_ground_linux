#include "object_detector.h"
#include <fstream>
#include <iostream>

ObjectDetector::ObjectDetector() {
    // COCO class names (subset)
    classes_ = {"background", "person", "bicycle", "car", "motorcycle",
                "airplane", "bus", "train", "truck", "boat",
                "traffic light", "fire hydrant", "stop sign", "parking meter", "bench",
                "bird", "cat", "dog", "horse", "sheep", "cow", "elephant", "bear",
                "zebra", "giraffe", "backpack", "umbrella", "handbag", "tie", "suitcase",
                "frisbee", "skis", "snowboard", "sports ball", "kite", "baseball bat",
                "baseball glove", "skateboard", "surfboard", "tennis racket", "bottle",
                "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple",
                "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut",
                "cake", "chair", "couch", "potted plant", "bed", "dining table",
                "toilet", "tv", "laptop", "mouse", "remote", "keyboard", "cell phone",
                "microwave", "oven", "toaster", "sink", "refrigerator", "book", "clock",
                "vase", "scissors", "teddy bear", "hair drier", "toothbrush"};
}

bool ObjectDetector::loadModel(const std::string& model_path, const std::string& config_path) {
    try {
        net_ = cv::dnn::readNet(model_path, config_path);
        net_.setPreferableBackend(cv::dnn::DNN_BACKEND_OPENCV);
        net_.setPreferableTarget(cv::dnn::DNN_TARGET_CPU);
        return true;
    } catch (const cv::Exception& e) {
        std::cerr << "Failed to load model: " << e.what() << std::endl;
        return false;
    }
}

std::vector<DetectedObject> ObjectDetector::detect(const cv::Mat& frame) {
    cv::Mat blob = cv::dnn::blobFromImage(frame, 1/255.0, cv::Size(416,416),
                                          cv::Scalar(0,0,0), true, false);
    net_.setInput(blob);
    std::vector<cv::Mat> outputs;
    net_.forward(outputs, net_.getUnconnectedOutLayersNames());

    std::vector<DetectedObject> detections;
    // Post-processing (simplified for YOLOv4)
    for (auto& out : outputs) {
        float* data = (float*)out.data;
        for (int i = 0; i < out.rows; ++i, data += out.cols) {
            float confidence = data[4];
            if (confidence > conf_threshold_) {
                int class_id = std::max_element(data+5, data+out.cols) - (data+5);
                float class_conf = data[5+class_id];
                if (class_conf > conf_threshold_) {
                    int center_x = (int)(data[0] * frame.cols);
                    int center_y = (int)(data[1] * frame.rows);
                    int width = (int)(data[2] * frame.cols);
                    int height = (int)(data[3] * frame.rows);
                    int x = center_x - width/2;
                    int y = center_y - height/2;
                    DetectedObject obj;
                    obj.bbox = cv::Rect(x, y, width, height);
                    obj.confidence = confidence * class_conf;
                    obj.class_id = class_id;
                    obj.label = classes_[class_id];
                    obj.tracked = false;
                    detections.push_back(obj);
                }
            }
        }
    }
    last_detections_ = detections;
    return detections;
}

void ObjectDetector::selectObject(int index) {
    if (index >= 0 && index < (int)last_detections_.size()) {
        tracked_index_ = index;
        last_detections_[index].tracked = true;
    }
}

DetectedObject* ObjectDetector::getTrackedObject() {
    if (tracked_index_ >= 0 && tracked_index_ < (int)last_detections_.size()) {
        return &last_detections_[tracked_index_];
    }
    return nullptr;
}

DetectedObject* ObjectDetector::selectObjectAtScreenCenter(int screen_w, int screen_h, float scale_x, float scale_y) {
    // Find object whose bounding box center is closest to screen center
    if (last_detections_.empty()) return nullptr;
    int cx = screen_w / 2;
    int cy = screen_h / 2;
    int best_idx = -1;
    float best_dist = 1e9;
    for (size_t i = 0; i < last_detections_.size(); i++) {
        cv::Rect& b = last_detections_[i].bbox;
        int obj_cx = (b.x + b.width/2) * scale_x;
        int obj_cy = (b.y + b.height/2) * scale_y;
        float dist = std::hypot(obj_cx - cx, obj_cy - cy);
        if (dist < best_dist) {
            best_dist = dist;
            best_idx = i;
        }
    }
    if (best_idx != -1) {
        selectObject(best_idx);
        return &last_detections_[best_idx];
    }
    return nullptr;
}

void ObjectDetector::clearTracking() {
    tracked_index_ = -1;
    for (auto& obj : last_detections_) obj.tracked = false;
}