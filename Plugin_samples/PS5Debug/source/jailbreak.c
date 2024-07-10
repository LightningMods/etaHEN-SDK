// Credits to astrelsky: https://github.com/astrelsky/HEN-V/blob/master/spawner/source/jailbreak.c
#include <ps5/kernel.h>
#include <stdlib.h>
#include "jailbreak.h"
#include "kern.h"

unsigned long
kernel_get_proc_filedesc(int pid) {
  unsigned long filedesc = 0;
  unsigned long proc = 0;

  if(!(proc=kernel_get_proc(pid))) {
    return 0;
  }

  if(kernel_copyout_ret(proc + KERNEL_OFFSET_PROC_P_FD, &filedesc,
		    sizeof(filedesc))) {
    return 0;
  }

  return filedesc;
}


void * malloc(size_t size);
static inline void copyin(uintptr_t kdst, void *src, size_t length) {
	kernel_copyin_ret(src, kdst, length);
}

void jailbreak_process(pid_t pid, bool escapeSandbox) {
	uintptr_t ucred = kernel_get_proc_ucred(pid);
	uintptr_t fd = kernel_get_proc_filedesc(pid);
	uint8_t * rootvnode_area_store = (uint8_t *)malloc(0x100);
	kernel_copyout_ret(KERNEL_ADDRESS_ROOTVNODE, rootvnode_area_store, 0x100);
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
}
