#include "auth.h"
#include "module.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_HANDLES 0x300

void *malloc(size_t size);
void free(void *ptr);
extern uintptr_t syscall_addr;

static int __attribute__((naked, noinline)) do_dl_get_list(int pid, int64_t *handles, uint32_t max_handles, uint32_t *num_handles) {
	__asm__ volatile(
		"mov $535, %rax\n"
		"jmp *syscall_addr(%rip)\n"
	);
}

static int __attribute__((naked, noinline)) do_dl_get_info_2(int pid, uint32_t sandboxed_path, int64_t handle, module_info_t *info) {
		__asm__ volatile(
		"mov $717, %rax\n"
		"jmp *syscall_addr(%rip)\n"
	);
}

static int dl_get_info_2(int pid, uint32_t sandboxed_path, int64_t handle, module_info_t *info) {
	const uintptr_t ucred = get_current_ucred();
	uint64_t id = ucred_swap_authid(ucred, DEBUGGER_AUTHID);
	int res = do_dl_get_info_2(pid, sandboxed_path, handle, info);
	ucred_swap_authid(ucred, id);
	return res;
}

static int dl_get_list(int pid, int64_t *handles, uint32_t max_handles, uint32_t *num_handles) {
	const uintptr_t ucred = get_current_ucred();
	uint64_t id = ucred_swap_authid(ucred, DEBUGGER_AUTHID);
	int res = do_dl_get_list(pid, handles, max_handles, num_handles);
	ucred_swap_authid(ucred, id);
	return res;
}

module_handle_list_t get_module_handles(int pid) {
	// nobody will have that many handles
	module_handle_list_t handles = malloc(MAX_HANDLES * sizeof(uint64_t));
	uint32_t numHandles = 0;
	if (dl_get_list(pid, handles, MAX_HANDLES, &numHandles) < 0) {
		perror("get_module_handles __sys_dl_get_list");
		free(handles);
		return NULL;
	}

	module_handle_list_t result = realloc(handles, (numHandles + 1) * sizeof(uint64_t));
	if (result == NULL) {
		// /shrug
		result = handles;
	}

	result[numHandles] = -1;
	return result;
}

int get_module_info(int pid, int64_t handle, module_info_t *info) {
	return dl_get_info_2(pid, 1, handle, info);
}

int64_t get_module_handle(int pid, const char *name, size_t length) {
	if (length > MODULE_INFO_NAME_LENGTH) {
		errno = EINVAL;
		return -1;
	}

	if (length == 0) {
		length = strnlen(name, MODULE_INFO_NAME_LENGTH);
	}

	module_handle_list_t handles = get_module_handles(pid);
	if (handles == NULL) {
		return -1;
	}

	module_info_t info;
	for (const int64_t *it = handles; *it != -1L; it++) {
		const int64_t handle = *it;
		if (get_module_info(pid, handle, &info)) {
			free(handles);
			return -1;
		}

		if (strncmp(name, info.filename, length) == 0) {
			free(handles);
			return handle;
		}
	}

	free(handles);
	return -1;
}
