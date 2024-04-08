#include "memory.h"
#include "offsets.h"
#include "proc.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

void* malloc(size_t size);
void free(void* ptr);

static inline void copyin(uintptr_t kdst, void *src, size_t length) {
	kernel_copyin(src, kdst, length);
}

// NOLINTBEGIN(readability-magic-numbers)

void jailbreak_process(uintptr_t proc, bool escapeSandbox) {
	uintptr_t ucred = proc_get_ucred(proc);
	uintptr_t fd = proc_get_fd(proc);
	uint8_t * rootvnode_area_store = malloc(0x100);
	kernel_copyout(kernel_base + get_root_vnode_offset(), rootvnode_area_store, 0x100);
	uint32_t uid_store = 0;
	uint32_t ngroups_store = 0;
	uint64_t authid_store = 0x4801000000000013L;
	int64_t caps_store = -1;
	uint8_t attr_store[] = {0x80, 0, 0, 0, 0, 0, 0, 0};

	copyin(ucred + 0x04, &uid_store, 0x4);		  // cr_uid
	copyin(ucred + 0x08, &uid_store, 0x4);		  // cr_ruid
	copyin(ucred + 0x0C, &uid_store, 0x4);		  // cr_svuid
	copyin(ucred + 0x10, &ngroups_store, 0x4);	  // cr_ngroups
	copyin(ucred + 0x14, &uid_store, 0x4);		  // cr_rgid

	if (escapeSandbox) {
		// Escape sandbox
		copyin(fd + 0x10, rootvnode_area_store, 0x8);  // fd_rdir
		copyin(fd + 0x18, rootvnode_area_store, 0x8);  // fd_jdir
	}

	// Escalate sony privileges
	copyin(ucred + 0x58, &authid_store, 0x8);	 // cr_sceAuthID
	copyin(ucred + 0x60, &caps_store, 0x8);		 // cr_sceCaps[0]
	copyin(ucred + 0x68, &caps_store, 0x8);		 // cr_sceCaps[1]
	copyin(ucred + 0x83, attr_store, 0x1);		 // cr_sceAttr[0]

	free(rootvnode_area_store);
}

// NOLINTEND(readability-magic-numbers)
