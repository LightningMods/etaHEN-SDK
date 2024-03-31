#include <fcntl.h>
#include <ps5/payload_main.h>
#include <stdint.h>
#include <stdlib.h>

// NOLINTBEGIN(*)

extern int main(int argc, const char **argv);

extern void (*__preinit_array_start[])(void) __attribute__((weak));
extern void (*__preinit_array_end[])(void) __attribute__((weak));
extern void (*__init_array_start[])(void) __attribute__((weak));
extern void (*__init_array_end[])(void) __attribute__((weak));
extern void (*__fini_array_start[])(void) __attribute__((weak));
extern void (*__fini_array_end[])(void) __attribute__((weak));
extern uint8_t __bss_start __attribute__((weak));
extern uint8_t __bss_end __attribute__((weak));

void payload_init(const struct payload_args *restrict args);

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

	exit(main(0, NULL));
	kill(getpid(), SIGKILL);
}
// NOLINTEND(*)
