#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace telemetry::ansi {

constexpr const char* green = "\x1b[32m";
constexpr const char* red = "\x1b[31m";
constexpr const char* yellow = "\x1b[33m";
constexpr const char* cyan = "\x1b[36m";
constexpr const char* magenta = "\x1b[35m";
constexpr const char* bold = "\x1b[1m";
constexpr const char* reset = "\x1b[0m";

inline void enable() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

}
