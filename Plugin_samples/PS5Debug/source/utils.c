#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdarg.h>
#include "utils.h"
#include "libsce_defs.h"


void *malloc(size_t size);

void prefault(void *address, size_t size) {
    for(uint64_t i = 0; i < size; i++) {
        volatile uint8_t c;
        (void)c;
        
        c = ((char *)address)[i];
    }
}

void *pfmalloc(size_t size) {
    void *p = malloc(size);
    prefault(p, size);
    return p;
}

void printf_notification(const char* fmt, ...) {
	OrbisNotificationRequest req;
	(void)memset(&req, 0, sizeof(OrbisNotificationRequest));
	char buff[3075];

	va_list args;
	va_start(args, fmt);
	vsnprintf(buff, sizeof(buff), fmt, args);
	va_end(args);

	req.type = 0;
	req.unk3 = 0;
	req.use_icon_image_uri = 1;
	req.target_id = -1;
	strcpy(req.uri, "cxml://psnotification/tex_icon_system");

	sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}