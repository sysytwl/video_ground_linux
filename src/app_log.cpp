#include "app_log.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

static std::mutex g_app_log_mutex;
static FILE* g_app_log_file = nullptr;

static bool app_log_enabled() {
    static int cached = -1;
    if (cached < 0) {
        const char* env = std::getenv("APP_LOG_DEBUG");
        if (env && *env) {
            cached = (std::strcmp(env, "0") != 0 && std::strcmp(env, "false") != 0 && std::strcmp(env, "off") != 0) ? 1 : 0;
        } else {
            cached = 1;
        }
    }
    return cached != 0;
}

static FILE* app_log_open_locked() {
    if (g_app_log_file) return g_app_log_file;
    const char* path = std::getenv("APP_LOG_FILE");
    if (!path || !*path) path = "log.txt";
    g_app_log_file = std::fopen(path, "w");
    return g_app_log_file;
}

void app_log(const char* tag, const char* format, ...) {
    if (!app_log_enabled()) return;

    std::lock_guard<std::mutex> lock(g_app_log_mutex);
    FILE* file = app_log_open_locked();
    if (!file) return;

    std::fprintf(file, "[%s] ", tag ? tag : "APP");
    va_list args;
    va_start(args, format);
    std::vfprintf(file, format, args);
    va_end(args);
    std::fprintf(file, "\n");
    std::fflush(file);
}

void app_log_bytes(const char* tag, const char* label, const uint8_t* data, size_t len) {
    if (!app_log_enabled()) return;

    std::lock_guard<std::mutex> lock(g_app_log_mutex);
    FILE* file = app_log_open_locked();
    if (!file) return;

    std::fprintf(file, "[%s] %s", tag ? tag : "APP", label ? label : "bytes");
    for (size_t i = 0; i < len; ++i) {
        std::fprintf(file, " %02X", data[i]);
    }
    std::fprintf(file, "\n");
    std::fflush(file);
}

void app_log_close() {
    std::lock_guard<std::mutex> lock(g_app_log_mutex);
    if (g_app_log_file) {
        std::fflush(g_app_log_file);
        std::fclose(g_app_log_file);
        g_app_log_file = nullptr;
    }
}