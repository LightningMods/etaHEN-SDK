// Credits to astrelsky: https://github.com/astrelsky/HEN-V/blob/master/spawner/source/memory.c
#include <stdio.h>
#include <string.h>

#include <ps5/kernel.h>

#include "mdbg.h"

#define DBG_ARG_DEFAULT_TYPE 1

#define DBG_CMD_READ 0x12
#define DBG_CMD_WRITE 0x13

#define DBG_ARG1_PAD_SIZE 0x10
#define DBG_ARG1_FULL_SIZE 0x20

#define DBG_ARG2_PAD_SIZE 0x20
#define DBG_ARG2_FULL_SIZE 0x40

#define DBG_ARG3_PAD_SIZE 0x10
#define DBG_ARG3_FULL_SIZE 0x20

typedef struct {
	uint32_t type;
	uint32_t pad1;
	uint64_t cmd;
	uint8_t __attribute__((unused)) pad[DBG_ARG1_PAD_SIZE];
} dbg_arg1_t;

typedef struct {
	int pid;
	uintptr_t src;
	void *dst;
	uint64_t length;
	unsigned char __attribute__((unused)) pad[DBG_ARG2_PAD_SIZE];
} dbg_arg2_t;

typedef struct {
	int64_t err;
	uint64_t length;
	unsigned char __attribute__((unused)) pad[DBG_ARG3_PAD_SIZE];
} dbg_arg3_t;

extern int mdbg_call(void *arg1, void *arg2, void *arg3);
static int do_mdbg_call(void *arg1, void *arg2, void *arg3) {
  pid_t pid = getpid();
  uint64_t authid;
  if(!(authid=kernel_get_ucred_authid(pid))) {
    return -1;
  }

  if(kernel_set_ucred_authid(pid, 0x4800000000000006l)) {
    return -1;
  }
	int res = syscall(573, arg1, arg2, arg3);
  if(kernel_set_ucred_authid(pid, authid)) {
    return -1;
  }
	return res;
}


void userland_copyin(int pid, const void *src, uintptr_t dst, size_t length) {
	dbg_arg1_t arg1;
	dbg_arg2_t arg2;
	dbg_arg3_t arg3;
	memset(&arg1, 0, sizeof(arg1));
	memset(&arg2, 0, sizeof(arg2));
	memset(&arg3, 0, sizeof(arg3));

	arg1 = (dbg_arg1_t) {
		.type = DBG_ARG_DEFAULT_TYPE,
		.cmd = DBG_CMD_WRITE
	};

	arg2 = (dbg_arg2_t) {
		.pid = pid,
		.src = dst,
		.dst = (void *)src,
		.length = length
	};

	if (do_mdbg_call(&arg1, &arg2, &arg3)) {
		puts("mdbg_call failed");
	}
}

void userland_copyout(int pid, uintptr_t src, void *dst, size_t length) {
	dbg_arg1_t arg1;
	dbg_arg2_t arg2;
	dbg_arg3_t arg3;
	memset(&arg1, 0, sizeof(arg1));
	memset(&arg2, 0, sizeof(arg2));
	memset(&arg3, 0, sizeof(arg3));

	arg1 = (dbg_arg1_t) {
		.type = DBG_ARG_DEFAULT_TYPE,
		.cmd = DBG_CMD_READ
	};

	arg2 = (dbg_arg2_t) {
		.pid = pid,
		.src = src,
		.dst = dst,
		.length = length
	};

	if (do_mdbg_call(&arg1, &arg2, &arg3)) {
		puts("mdbg_call failed");
	}
}