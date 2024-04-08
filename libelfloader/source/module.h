#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#define MODULE_INFO_NAME_LENGTH 128
#define MODULE_INFO_SANDBOXED_PATH_LENGTH 1024
#define MODULE_INFO_MAX_SECTIONS 4
#define FINGERPRINT_LENGTH 20

// A -1L terminated list of module handles
typedef int64_t *module_handle_list_t;

typedef struct {
	uintptr_t vaddr;
	uint32_t size;
	uint32_t prot;
} module_section_t;

typedef struct {
	char filename[MODULE_INFO_NAME_LENGTH];
	uint64_t handle;
	uint8_t unknown0[32]; // NOLINT(readability-magic-numbers)
	uintptr_t unknown1; // init
	uintptr_t unknown2; // fini
	uintptr_t unknown3; // eh_frame_hdr
	uintptr_t unknown4; // eh_frame_hdr_sz
	uintptr_t unknown5; // eh_frame
	uintptr_t unknown6; // eh_frame_sz
	module_section_t sections[MODULE_INFO_MAX_SECTIONS];
	uint8_t unknown7[1176]; // NOLINT(readability-magic-numbers)
	uint8_t fingerprint[FINGERPRINT_LENGTH];
	uint32_t unknown8;
	char libname[MODULE_INFO_NAME_LENGTH];
	uint32_t unknown9;
	char sandboxed_path[MODULE_INFO_SANDBOXED_PATH_LENGTH];
	uint64_t sdk_version;
} module_info_t;

//static_assert(sizeof(module_info_t) == 0xa58, "sizeof(module_info_t) != 0xa58"); // NOLINT(readability-magic-numbers)

module_handle_list_t get_module_handles(int pid);
int get_module_info(int pid, int64_t handle, module_info_t *info);
int64_t get_module_handle(int pid, const char *name, size_t length);
