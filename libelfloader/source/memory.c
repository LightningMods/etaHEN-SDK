#include "auth.h"
#include "memory.h"
#include "proc.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

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

//static_assert(sizeof(dbg_arg1_t) == DBG_ARG1_FULL_SIZE, "sizeof(dbg_arg1_t) != 0x20");

typedef struct {
	int pid;
	uintptr_t src;
	void *dst;
	uint64_t length;
	unsigned char __attribute__((unused)) pad[DBG_ARG2_PAD_SIZE];
} dbg_arg2_t;

//static_assert(sizeof(dbg_arg2_t) == DBG_ARG2_FULL_SIZE, "sizeof(DbgReadArg) != 0x40");

typedef struct {
	int64_t err;
	uint64_t length;
	unsigned char __attribute__((unused)) pad[DBG_ARG3_PAD_SIZE];
} dbg_arg3_t;

//static_assert(sizeof(dbg_arg3_t) == DBG_ARG3_FULL_SIZE, "sizeof(DbgArg3) != 0x20");

extern int mdbg_call(void *arg1, void *arg2, void *arg3);

static int do_mdbg_call(void *arg1, void *arg2, void *arg3) {
	const uintptr_t ucred = get_current_ucred();
	uint64_t id = ucred_swap_authid(ucred, DEBUGGER_AUTHID);
	int res = mdbg_call(arg1, arg2, arg3);
	ucred_swap_authid(ucred, id);
	return res;
}


void userland_copyin(int pid, const void *src, uintptr_t dst, size_t length) {
	dbg_arg1_t arg1;
	dbg_arg2_t arg2;
	dbg_arg3_t arg3;
	(void)memset(&arg1, 0, sizeof(arg1));
	(void)memset(&arg2, 0, sizeof(arg2));
	(void)memset(&arg3, 0, sizeof(arg3));

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
	(void)memset(&arg1, 0, sizeof(arg1));
	(void)memset(&arg2, 0, sizeof(arg2));
	(void)memset(&arg3, 0, sizeof(arg3));

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

uintptr_t get_current_proc(void) {
	static uintptr_t g_current_proc = 0;
	if (g_current_proc != 0) {
		return g_current_proc;
	}
	g_current_proc = get_proc(getpid());
	return g_current_proc;
}

uintptr_t get_parent_proc(void) {
	static uintptr_t g_parent_proc = 0;
	if (g_parent_proc != 0) {
		return g_parent_proc;
	}
	g_parent_proc = get_proc(getppid());
	return g_parent_proc;
}
