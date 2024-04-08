#pragma once

#include "memory.h"
#include <stdint.h>
#include <unistd.h>

#define SHARED_LIB_IMAGEBASE_OFFSET 0x30
#define SHARED_LIB_METADATA_OFFSET 0x148
#define TITLEID_SIZE 9

typedef struct {
	uintptr_t page_end;
	size_t consumed;
} process_allocator_t;

static inline uintptr_t shared_object_get_eboot(uintptr_t obj) {
	uintptr_t eboot = 0;
	kernel_copyout(obj, &eboot, sizeof(eboot));
	return eboot;
}

static inline uintptr_t shared_lib_get_next(uintptr_t lib) {
	uintptr_t next = 0;
	kernel_copyout(lib, &next, sizeof(next));
	return next;
}

static inline uintptr_t shared_lib_get_metadata(uintptr_t lib) {
	uintptr_t meta = 0;
	kernel_copyout(lib + SHARED_LIB_METADATA_OFFSET, &meta, sizeof(meta));
	return meta;
}

static inline uintptr_t shared_lib_get_imagebase(uintptr_t lib) {
	uintptr_t imagebase = 0;
	kernel_copyout(lib + SHARED_LIB_IMAGEBASE_OFFSET, &imagebase, sizeof(imagebase));
	return imagebase;
}

size_t metadata_get_plt_offset(uintptr_t meta, const char *sym_nid);
uintptr_t shared_lib_get_address(uintptr_t lib, const char *sym_nid);

int get_text_allocator(process_allocator_t *restrict self, uintptr_t proc);
int get_data_allocator(process_allocator_t *restrict self, uintptr_t proc);

uintptr_t process_allocator_allocate(process_allocator_t *restrict self, size_t length);
