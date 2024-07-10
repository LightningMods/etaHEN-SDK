#include <fcntl.h>
#include <ps5/payload_main.h>
#include <stdint.h>
#include <stdlib.h>
#include <ps5/kernel.h>
// NOLINTBEGIN(*)

extern int main(int argc, const char **argv);

uint64_t kernel_base = 0;

extern void (*__preinit_array_start[])(void) __attribute__((weak));
extern void (*__preinit_array_end[])(void) __attribute__((weak));
extern void (*__init_array_start[])(void) __attribute__((weak));
extern void (*__init_array_end[])(void) __attribute__((weak));
extern void (*__fini_array_start[])(void) __attribute__((weak));
extern void (*__fini_array_end[])(void) __attribute__((weak));
extern uint8_t __bss_start __attribute__((weak));
extern uint8_t __bss_end __attribute__((weak));

void payload_init(const struct payload_args *restrict args) {
	kernel_base = args->kdata_base_addr;
	kernel_init_rw(args->rwpair[0], args->rwpair[1], args->rwpipe, args->kpipe_addr);
}


static void _preinit(void) {
	const size_t length = __preinit_array_end - __preinit_array_start;
	for (size_t i = 0; i < length; i++) {
		__preinit_array_start[i]();
	}
}

static void _init(void) {
	const size_t length = __init_array_end - __init_array_start;
	for (size_t i = 0; i < length; i++) {
		__init_array_start[i]();
	}
}

static void _fini(void) {
	const size_t length = __fini_array_end - __fini_array_start;
	for (size_t i = 0; i < length; i++) {
		__fini_array_start[i]();
	}
}
void* syscall_addr = NULL;
int __kernel_init(const struct payload_args* args);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wlanguage-extension-token"
asm(".intel_syntax noprefix\n"
    ".global syscall\n"
    ".type syscall @function\n"
    "syscall:\n"
    "  mov rax, rdi\n"
    "  mov rdi, rsi\n"
    "  mov rsi, rdx\n"
    "  mov rdx, rcx\n"
    "  mov r10, r8\n"
    "  mov r8,  r9\n"
    "  mov r9,  qword ptr [rsp + 8]\n"
    "  jmp qword ptr [rip + syscall_addr]\n"
    "  ret\n"
    );
#pragma clang diagnostic pop
void _start(const struct payload_args *restrict args) {
	int fd = open("/dev/console", O_WRONLY);
	if (fd == -1) {
		exit(0);
		kill(getpid(), SIGKILL);
	}

	dup2(fd, STDOUT_FILENO);
	dup2(STDOUT_FILENO, STDERR_FILENO);

	payload_init(args);


	// preinit and then init
	_preinit();
	_init();

	// register _fini
	atexit(_fini);

	char* get_authinfo = 0;
	args->dlsym(0x2001, "get_authinfo", &get_authinfo);
	syscall_addr = get_authinfo + 7;

	exit(main(0, NULL));
	kill(getpid(), SIGKILL);
}
