#include "auth.h"
#include "libs.h"
#include "proc.h"
#include "tracer.h"

#include <errno.h>
#include <machine/reg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#define GET_AUTHINFO_NID "igMefp4SAv0"
#define ERRNO_NID "9BcDykPmo1I"
#define SYSCALL_OFFSET 10

#define JITSHM_CREATE 533
#define JITSHM_ALIAS 534
#define MMAP 477
#define MUNMAP 73
#define MPROTECT 74
#define CLOSE 6
#define SOCKET 97
#define PIPE 42
#define PIPE2 687
#define SETSOCKOPT 105

static uintptr_t tracer_start_call(tracer_t *restrict self, const reg_t *restrict backup, reg_t *restrict jmp);
static uintptr_t tracer_start_syscall(tracer_t *restrict self, const reg_t *restrict backup, reg_t *restrict jmp);
static uintptr_t tracer_syscall(tracer_t *restrict self, uintptr_t num, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f);

int tracer_ptrace(const tracer_t *restrict self, int request, pid_t pid, caddr_t addr, int data) {
	//uint64_t id = ucred_swap_authid(get_current_ucred(), PTRACE_ID);
	(void)self;
	int res = ptrace(request, pid, addr, data);
	//ucred_swap_authid(get_current_ucred(), id);
	return res;
}

static void set_args(reg_t *restrict regs, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
	regs->r_rdi = (register_t) a;
	regs->r_rsi = (register_t) b;
	regs->r_rdx = (register_t) c;
	regs->r_rcx = (register_t) d;
	regs->r_r8 = (register_t) e;
	regs->r_r9 = (register_t) f;
}

uintptr_t tracer_call(tracer_t *restrict self, uintptr_t addr, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
	if (addr == 0) {
		errno = EINVAL;
		return (uintptr_t)-1L;
	}
	reg_t jmp;
	tracer_get_registers(self, &jmp);
	const reg_t backup = jmp;
	jmp.r_rip = (register_t) addr;
	set_args(&jmp, a, b, c, d, e, f);
	return tracer_start_call(self, &backup, &jmp);
}
// any remaining attempts to use the templated call will fail

int tracer_init(tracer_t *restrict self, int pid) {
	uintptr_t current_ucred = get_current_ucred();
	*self = (tracer_t) {
		.original_authid = ucred_swap_authid(current_ucred, PTRACE_ID),
		.syscall_addr = 0,
		.libkernel_base = 0,
		.errno_addr = 0,
		.pid = pid
	};

	if (pid == getpid()) {
		self->pid = 0;
	} else {
		if (tracer_ptrace(self, PT_ATTACH, self->pid, 0, 0) < 0) {
			perror("ptrace PT_ATTACH tracer_init");
			ucred_set_authid(current_ucred, self->original_authid);
			self->pid = 0;
			return -1;
		}
		return tracer_wait(self, 0);
	}
	return 0;
}

int tracer_finalize(tracer_t *restrict self) {
	if (self->pid) {
		if (tracer_ptrace(self, PT_DETACH, self->pid, 0, 0) < 0) {
			perror("ptrace PT_DETACH tracer_finalize");
			ucred_set_authid(get_current_ucred(), self->original_authid);
			return -1;
		}
		ucred_set_authid(get_current_ucred(), self->original_authid);
	}
	return 0;
}

int tracer_wait(const tracer_t *restrict self, int options) {
	int status = 0;
	if (waitpid(self->pid, &status, options) < 0) {
		perror("waitpid");
		return -1;
	}
	return status;
}

int tracer_jitshm_create(tracer_t *restrict self, uintptr_t name, size_t size, int flags) {
	return (int) tracer_syscall(self, JITSHM_CREATE, name, size, flags, 0, 0, 0);
}

int tracer_jitshm_alias(tracer_t *restrict self, int fd, int flags) {
	return (int) tracer_syscall(self, JITSHM_ALIAS, fd, flags, 0, 0, 0, 0);
}

uintptr_t tracer_mmap(tracer_t *restrict self, uintptr_t addr, size_t len, int prot, int flags, int fd, off_t off) {
	return tracer_syscall(self, MMAP, addr, len, prot, flags, fd, off);
}

int tracer_munmap(tracer_t *restrict self, uintptr_t addr, size_t len) {
	return (int) tracer_syscall(self, MUNMAP, addr, len, 0, 0, 0, 0);
}

int tracer_mprotect(tracer_t *restrict self, uintptr_t addr, size_t len, int prot) {
	return (int) tracer_syscall(self, MPROTECT, addr, len, prot, 0, 0, 0);
}

int tracer_close(tracer_t *restrict self, int fd) {
	return (int) tracer_syscall(self, CLOSE, fd, 0, 0, 0, 0, 0);
}

int tracer_socket(tracer_t *restrict self, int domain, int type, int protocol) {
	return (int) tracer_syscall(self, SOCKET, domain, type, protocol, 0, 0, 0);
}

static uintptr_t tracer_start_call(tracer_t *restrict self, const reg_t *restrict backup, reg_t *restrict jmp) {
	if (self->libkernel_base == 0) {
		uintptr_t proc = get_proc(self->pid);
		if (proc == 0) {
			puts("failed to get traced proc");
			return -1;
		}
		uintptr_t lib = proc_get_lib(proc, LIBKERNEL_HANDLE);
		if (lib == 0) {
			puts("failed to get libkernel for traced proc");
			return -1;
		}
		self->libkernel_base = shared_lib_get_imagebase(lib);
		if (self->libkernel_base == 0) {
			puts("failed to get libkernel base for traced proc");
			return -1;
		}
	}

	jmp->r_rsp = (register_t) (jmp->r_rsp - sizeof(uintptr_t));

	if (tracer_set_registers(self, jmp)) {
		perror("tracer_start_call set registers failed");
		return -1;
	}

	// set the return address to the `INT3` at the start of libkernel
	userland_copyin(self->pid, &self->libkernel_base, jmp->r_rsp, sizeof(self->libkernel_base));

	// call the function
	int state = tracer_continue(self, true);

	if (!WIFSTOPPED(state)) {
		puts("process not stopped");
		return -1;
	}

	if (WSTOPSIG(state) != SIGTRAP) {
		printf("process received signal %d but SIGTRAP was expected\n", WSTOPSIG(state));
		return -1;
	}

	if (tracer_get_registers(self, jmp)) {
		perror("tracer_start_call get registers failed");
		return -1;
	}

	// restore registers
	if (tracer_set_registers(self, backup)) {
		perror("tracer_start_call set registers failed");
		return -1;
	}

	return jmp->r_rax;
}

static uintptr_t tracer_start_syscall(tracer_t *restrict self, const reg_t *restrict backup, reg_t *restrict jmp) {
	if (self->syscall_addr == 0) {
		uintptr_t proc = get_proc(self->pid);
		if (proc == 0) {
			puts("failed to get traced proc");
			return -1;
		}
		uintptr_t lib = proc_get_lib(proc, LIBKERNEL_HANDLE);
		if (lib == 0) {
			puts("failed to get libkernel for traced proc");
			return -1;
		}
		uintptr_t addr = shared_lib_get_address(lib, GET_AUTHINFO_NID);
		if (addr == 0) {
			puts("failed to get syscall address for traced proc");
			return -1;
		}
		if (addr != 0) {
			addr += SYSCALL_OFFSET;
		}
		self->syscall_addr = addr;
	}

	jmp->r_rip = (register_t) self->syscall_addr;

	if (tracer_set_registers(self, jmp)) {
		perror("tracer_start_syscall set registers failed");
		return -1;
	}

	// execute the syscall instruction
	tracer_step(self);
	if (tracer_get_registers(self, jmp)) {
		perror("tracer_start_syscall get registers failed");
		tracer_set_registers(self, backup);
		return -1;
	}

	// restore registers
	if (tracer_set_registers(self, backup)) {
		perror("tracer_start_syscall set registers failed");
		return -1;
	}

	return jmp->r_rax;
}

static uintptr_t tracer_syscall(tracer_t *restrict self, uintptr_t num, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
	reg_t jmp;
	tracer_get_registers(self, &jmp);
	const reg_t backup = jmp;
	set_args(&jmp, a, b, c, d, e, f);
	jmp.r_rax = (register_t)num;
	jmp.r_r10 = jmp.r_rcx;
	return tracer_start_syscall(self, &backup, &jmp);
}

void tracer_perror(tracer_t *restrict self, const char *msg) {
	if (self->errno_addr == 0) {
		uintptr_t proc = get_proc(self->pid);
		if (proc == 0) {
			puts("failed to get traced proc");
			return;
		}
		uintptr_t lib = proc_get_lib(proc, LIBKERNEL_HANDLE);
		if (lib == 0) {
			puts("failed to get libkernel for traced proc");
			return;
		}
		uintptr_t addr = shared_lib_get_address(lib, ERRNO_NID);
		if (addr == 0) {
			puts("failed to get errno address for traced proc");
			return;
		}
		self->errno_addr = addr;
	}
	uintptr_t p_errno = 0;
	userland_copyout(self->pid, self->errno_addr, &p_errno, sizeof(p_errno));

	int err = 0;
	userland_copyout(self->pid, p_errno, &err, sizeof(err));
	printf("%s: %s\n", msg, strerror(err)); // NOLINT(concurrency-mt-unsafe)
}

int tracer_pipe(tracer_t *restrict self, int *fildes) {
	fildes[0] = -1;
	fildes[1] = -1;

	reg_t jmp;
	tracer_get_registers(self, &jmp);
	const reg_t backup = jmp;

	const uintptr_t rsp = jmp.r_rsp - sizeof(long[2]);
	userland_copyin(self->pid, fildes, rsp, sizeof(int[2]));
	jmp.r_rax = PIPE2;
	jmp.r_rdi = (register_t)rsp;
	jmp.r_rsi = 0;
	int err = (int) tracer_start_syscall(self, &backup, &jmp);
	if (err < 0) {
		return err;
	}
	userland_copyout(self->pid, rsp, fildes, sizeof(int[2]));
	return 0;
}

int tracer_setsockopt(tracer_t *restrict self, int s, int level, int optname, const void *optval, unsigned int optlen) {
	reg_t jmp;
	tracer_get_registers(self, &jmp);
	const reg_t backup = jmp;
	const uintptr_t rsp = jmp.r_rsp - optlen;
	jmp.r_rax = SETSOCKOPT;
	jmp.r_rsp = (register_t) rsp;
	jmp.r_rdi = s;
	jmp.r_rsi = level;
	jmp.r_rdx = optname;
	jmp.r_r10 = (register_t) rsp;
	jmp.r_r8 = optlen;
	userland_copyin(self->pid, optval, rsp, optlen);
	int err = (int) tracer_start_syscall(self, &backup, &jmp);
	if (err < 0) {
		return err;
	}
	return 0;
}

void tracer_dump_registers(const reg_t *restrict regs) {
	printf("rax: 0x%08llx\n", regs->r_rax);
	printf("rbx: 0x%08llx\n", regs->r_rbx);
	printf("rcx: 0x%08llx\n", regs->r_rcx);
	printf("rdx: 0x%08llx\n", regs->r_rdx);
	printf("rsi: 0x%08llx\n", regs->r_rsi);
	printf("rdi: 0x%08llx\n", regs->r_rdi);
	printf("r8:  0x%08llx\n", regs->r_r8);
	printf("r9:  0x%08llx\n", regs->r_r9);
	printf("r10: 0x%08llx\n", regs->r_r10);
	printf("r11: 0x%08llx\n", regs->r_r11);
	printf("r12: 0x%08llx\n", regs->r_r12);
	printf("r13: 0x%08llx\n", regs->r_r13);
	printf("r14: 0x%08llx\n", regs->r_r14);
	printf("r15: 0x%08llx\n", regs->r_r15);
	printf("rbp: 0x%08llx\n", regs->r_rbp);
	printf("rsp: 0x%08llx\n", regs->r_rsp);
	printf("rip: 0x%08llx\n", regs->r_rip);
}
