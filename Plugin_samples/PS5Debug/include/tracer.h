// Credits to astrelsky: https://github.com/astrelsky/HEN-V/blob/master/spawner/source/tracer.h
#pragma once

#include <stdbool.h>
#include <sys/types.h>
#include <machine/reg.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

typedef struct {
	uint64_t original_authid;
	uintptr_t syscall_addr;
	uintptr_t libkernel_base;
	uintptr_t errno_addr;
	int pid;
} tracer_t;

typedef struct reg reg_t;

int tracer_init(tracer_t *restrict self, int pid);
int tracer_finalize(tracer_t *restrict self);
int tracer_wait(const tracer_t *restrict self, int options);
int tracer_ptrace(const tracer_t *restrict self, int request, pid_t pid, caddr_t addr, int data);
uintptr_t tracer_call(tracer_t *restrict self, uintptr_t addr, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f);

int trace(int request, pid_t pid, caddr_t addr, int data); 

static inline int tracer_get_registers(const tracer_t *restrict self, reg_t *restrict registers) {
	return tracer_ptrace(self, PT_GETREGS, self->pid, (caddr_t)registers, 0);
}

static inline int tracer_set_registers(const tracer_t *restrict self, const reg_t *restrict registers) {
	return tracer_ptrace(self, PT_SETREGS, self->pid, (caddr_t)(registers), 0);
}

static inline int tracer_step(const tracer_t *restrict self) {
	int res = tracer_ptrace(self, PT_STEP, self->pid, (caddr_t) 1, 0);
	if (res) {
		return res;
	}
	return tracer_wait(self, 0);
}

static inline int tracer_continue(const tracer_t *restrict self, bool wait) {
	int res = tracer_ptrace(self, PT_CONTINUE, self->pid, (caddr_t) 1, 0);
	if (res) {
		return res;
	}
	if (wait) {
		return tracer_wait(self, 0);
	}
	return tracer_wait(self, WNOHANG);
}

static inline int tracer_kill(const tracer_t *restrict self) {
	return tracer_ptrace(self, PT_KILL, self->pid, 0, 0);
}

int tracer_jitshm_create(tracer_t *restrict self, uintptr_t name, size_t size, int flags);
int tracer_jitshm_alias(tracer_t *restrict self, int fd, int flags);
uintptr_t tracer_mmap(tracer_t *restrict self, uintptr_t addr, size_t len, int prot, int flags, int fd, off_t off);
int tracer_munmap(tracer_t *restrict self, uintptr_t addr, size_t len);
int tracer_mprotect(tracer_t *restrict self, uintptr_t addr, size_t len, int prot);
int tracer_close(tracer_t *restrict self, int fd);
int tracer_socket(tracer_t *restrict self, int domain, int type, int protocol);
int tracer_pipe(tracer_t *restrict self, int *fildes);
int tracer_setsockopt(tracer_t *restrict self, int s, int level, int optname, const void *optval, unsigned int optlen);
void tracer_perror(tracer_t *restrict self, const char *msg);