#pragma once

#include "memory.h"
#include "rtld.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define PROC_PID_OFFSET 0xbc
#define PROC_FD_OFFSET 0x48
#define PROC_SHARED_OBJECT_OFFSET 0x3e8
#define PROC_SELFINFO_NAME_OFFSET 0x59C
#define PROC_SELFINFO_NAME_SIZE 32

uintptr_t proc_get_lib(uintptr_t proc, int handle);

uintptr_t get_proc(int target_pid);

static inline int proc_get_pid(uintptr_t proc) {
	int pid = 0;
	kernel_copyout(proc + PROC_PID_OFFSET, &pid, sizeof(pid));
	return pid;
}

static inline uintptr_t proc_get_next(uintptr_t proc) {
	uintptr_t next = 0;
	kernel_copyout(proc, &next, sizeof(next));
	return next;
}

static inline uintptr_t proc_get_shared_object(uintptr_t proc) {
	uintptr_t obj = 0;
	kernel_copyout(proc + PROC_SHARED_OBJECT_OFFSET, &obj, sizeof(obj));
	return obj;
}

static inline uintptr_t proc_get_eboot(uintptr_t proc) {
	uintptr_t obj = proc_get_shared_object(proc);
	if (obj == 0) {
		return 0;
	}
	return shared_object_get_eboot(obj);
}

static inline void proc_set_name(uintptr_t proc, const char *name) {
	const size_t name_length = strlen(name);
	const size_t length = name_length < (PROC_SELFINFO_NAME_SIZE-1) ? name_length : PROC_SELFINFO_NAME_SIZE;
	kernel_copyin((void*)name, proc + PROC_SELFINFO_NAME_OFFSET, length + 1);
}

static inline void proc_get_name(uintptr_t proc, char name[PROC_SELFINFO_NAME_SIZE]) {
	kernel_copyout(proc + PROC_SELFINFO_NAME_OFFSET, name, PROC_SELFINFO_NAME_SIZE);
}

static inline uintptr_t proc_get_fd(uintptr_t proc) {
	uintptr_t fd = 0;
	kernel_copyout(proc + PROC_FD_OFFSET, &fd, sizeof(fd));
	return fd;
}

uintptr_t get_current_proc(void);
uintptr_t get_parent_proc(void);
