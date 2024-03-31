#pragma once

#include <stdio.h> // IWYU pragma: keep

// NOLINTBEGIN(*)
#define __MACRO_STRINGIFY__(x) #x
#define __FILE_LINE_STRING__(x, y) x":"__MACRO_STRINGIFY__(y)
#define LOG_PERROR(msg) perror("[HEN-V UTIL] " __FILE_LINE_STRING__(__FILE_NAME__, __LINE__) ": " msg)
#define LOG_PRINTLN(msg) puts("[HEN-V UTIL] " __FILE_LINE_STRING__(__FILE_NAME__, __LINE__) ": " msg)
#define LOG_PRINTF(msg, ...) printf("[HEN-V UTIL] " __FILE_LINE_STRING__(__FILE_NAME__, __LINE__) ": " msg, __VA_ARGS__)
// NOLINTEND(*)
