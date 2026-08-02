#ifndef APP_LOG_H
#define APP_LOG_H

#include <cstddef>
#include <cstdint>

void app_log(const char* tag, const char* format, ...);
void app_log_bytes(const char* tag, const char* label, const uint8_t* data, size_t len);
void app_log_close();

#endif