#ifndef OBJECT_DETECTOR_H
#define OBJECT_DETECTOR_H

#include <opencv2/dnn.hpp>
#include <opencv2/imgproc.hpp>
#include <vector>
#include <string>

struct DetectedObject {
    cv::Rect bbox;
    float confidence;
    int class_id;
    std::string label;
    bool tracked;          // whether user is tracking this object
};

class ObjectDetector {
public:
    ObjectDetector();
    bool loadModel(const std::string& model_path, const std::string& config_path);
    std::vector<DetectedObject> detect(const cv::Mat& frame);
    
    // For tracking: select object via gamepad
    void selectObject(int index);
    DetectedObject* getTrackedObject();
    DetectedObject* selectObjectAtScreenCenter(int screen_w, int screen_h, float scale_x, float scale_y);
    void clearTracking();

private:
    cv::dnn::Net net_;
    std::vector<std::string> classes_;
    float conf_threshold_ = 0.5;
    std::vector<DetectedObject> last_detections_;
    int tracked_index_ = -1;
};

#endif