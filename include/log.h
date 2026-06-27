#ifndef LOG_H
#define LOG_H

#include "platform.h"

void log_init_ui(void *ui_handle);
void log_append(const char *fmt, ...);
void log_clear(void);

#endif
