#pragma once
#include "proc.h"
#include "ucred.h"

#include <stdint.h>
#include <unistd.h>

#define DEBUGGER_AUTHID 0x4800000000000006
#define PTRACE_ID 0x4800000000010003l

static inline uint64_t ucred_swap_authid(uintptr_t ucred, uint64_t id) {
	uint64_t old_id = ucred_get_authid(ucred);
	ucred_set_authid(ucred, id);
	return old_id;
}

static inline uint64_t proc_swap_authid(uintptr_t proc, uint64_t id) {
	uint64_t ucred = proc_get_ucred(proc);
	return ucred_swap_authid(ucred, id);
}

static inline uint64_t swap_authid(uint64_t id) {
	uintptr_t proc = get_proc(getpid());
	return proc_swap_authid(proc, id);
}
