#include "log.h"
#include "memory.h"
#include "tcp.h"

#include <unistd.h>

#define KRW_PORT 1338
#define FILEDESCENT_LENGTH 0x30
#define PROC_FD_OFFSET 0x48
#define PROC_PID_OFFSET 0xbc

typedef struct kernelrw_request {
	int pid;
	int master;
	int victim;
} kernelrw_request_t;

extern const size_t allprocOffset;

static uint32_t kread_uint32(uintptr_t addr) {
	uint32_t res = 0;
	kernel_copyout(addr, &res, sizeof(res));
	return res;
}

static void kwrite_uint32(uintptr_t addr, uint32_t value) {
	kernel_copyin(&value, addr, sizeof(value));
}

static uintptr_t kread_uintptr(uintptr_t addr) {
	uintptr_t res = 0;
	kernel_copyout(addr, &res, sizeof(res));
	return res;
}

static void kwrite_uintptr(uintptr_t addr, uintptr_t value) {
	kernel_copyin(&value, addr, sizeof(value));
}

static size_t get_num_files(uintptr_t tbl) {
	return (size_t)kread_uintptr(tbl);
}

static uintptr_t get_file(uintptr_t tbl, uintptr_t fd) {
	const size_t num_files = get_num_files(tbl);
	if (fd >= num_files) {
		return 0;
	}
	const uintptr_t fp = tbl + (fd * FILEDESCENT_LENGTH) + sizeof(uintptr_t);
	return kread_uintptr(fp);
}

static uintptr_t get_file_data(uintptr_t tbl, uintptr_t fd) {
	const uintptr_t file = get_file(tbl, fd);
	return file ? kread_uintptr(file) : 0;
}

static uintptr_t get_fd_tbl(uintptr_t fd) {
	return kread_uintptr(fd);
}

static uintptr_t proc_get_fd(uintptr_t proc) {
	return kread_uintptr(proc + PROC_FD_OFFSET);
}

static int proc_get_pid(uintptr_t proc) {
	return (int)kread_uint32(proc + PROC_PID_OFFSET);
}

static uintptr_t proc_get_next(uintptr_t proc) {
	return kread_uintptr(proc);
}

static uintptr_t get_proc(int target_pid) {
	for (uintptr_t proc = kread_uintptr(kernel_base + allprocOffset); proc; proc = proc_get_next(proc)) {
		if (proc_get_pid(proc) == target_pid) {
			return proc;
		}
	}
	return 0;
}

static const char *create_read_write_sockets(uintptr_t proc, int master, int victim) {
	// NOLINTBEGIN(readability-magic-numbers)
	const uintptr_t fd = proc_get_fd(proc);
	if (fd == 0) {
		return "proc->p_fd is NULL";
	}
	uintptr_t newtbl = get_fd_tbl(fd);
	if (newtbl == 0) {
		return "proc->p_fd->fd_files is NULL";
	}
	uintptr_t sock = get_file_data(newtbl, master);
	if (sock == 0) {
		return "master socket file data is NULL";
	}
	kwrite_uint32(sock, 0x100);
	uintptr_t pcb = kread_uintptr(sock + 0x18);
	if (pcb == 0) {
		return "master pcb is NULL";
	}
	uintptr_t master_inp6_outputopts = kread_uintptr(pcb + 0x120);
	if (master_inp6_outputopts == 0) {
		return "master inp6_outputopts is NULL";
	}
	sock = get_file_data(newtbl, victim);
	if (sock == 0) {
		return "victim socket file data is NULL";
	}
	kwrite_uint32(sock, 0x100);
	pcb = kread_uintptr(sock + 0x18);
	if (pcb == 0) {
		return "victim pcb is NULL";
	}
	uintptr_t victim_inp6_outputopts = kread_uintptr(pcb + 0x120);
	if (victim_inp6_outputopts == 0) {
		return "victim inp6_outputopts is NULL";
	}
	kwrite_uintptr(master_inp6_outputopts + 0x10, victim_inp6_outputopts + 0x10);
	kwrite_uint32(master_inp6_outputopts + 0xc0, 0x13370000);
	return NULL;
	// NOLINTEND(readability-magic-numbers)
}

static int send_error(const tcp_socket_t *restrict sock, const char *err, uint32_t length) {
	const uint64_t base = 0;
	if (tcp_write(sock, &base, sizeof(base))) {
		LOG_PRINTLN("tcp_write failed");
		return -1;
	}
	if (tcp_write(sock, &length, sizeof(length))) {
		LOG_PRINTLN("tcp_write failed");
		return -1;
	}
	if (tcp_write(sock, err, length)) {
		LOG_PRINTLN("tcp_write failed");
		return -1;
	}
	return 0;
}

static int setup_client_kernelrw(const tcp_socket_t *restrict sock) {
	kernelrw_request_t req = {
		.pid = 0,
		.master = 0,
		.victim = 0
	};

	if (tcp_read(sock, &req, sizeof(req))) {
		LOG_PRINTLN("tcp_read failed");
		return -1;
	}
	LOG_PRINTF("handling kernelrw request for pid %d, master: %d, victim: %d\n", req.pid, req.master, req.victim);
	const uintptr_t proc = get_proc(req.pid);
	if (proc == 0) {
		const char *err = "failed to find proc for kernelrw request";
		const uint32_t length = __builtin_strlen(err) + 1;
		if (send_error(sock, err, length)) {
			LOG_PRINTLN("send_error failed");
		}
		return 0;
	}
	const char *err = create_read_write_sockets(proc, req.master, req.victim);
	if (err) {
		const uint32_t length = __builtin_strlen(err) + 1;
		if (send_error(sock, err, length)) {
			LOG_PRINTLN("send_error failed");
		}
		return 0;
	}
	if (tcp_write(sock, &kernel_base, sizeof(kernel_base))) {
		LOG_PRINTLN("tcp_write failed");
	}
	return 0;
}

void *krw_server(void *args) {
	(void) args;
	// check first so if it's not supported this thread can just exit
	if (allprocOffset == (size_t)-1) {
		LOG_PRINTLN("kernel version not supported; unknown allproc offset");
		return NULL;
	}
	tcp_socket_t sock;
	if (tcp_init(&sock, 1, KRW_PORT)) {
		LOG_PRINTLN("tcp_init failed");
		return NULL;
	}
	for (;;) {
		const int err = tcp_accept(&sock);
		if (err) {
			if (err != REST_MODE_ERR) {
				LOG_PRINTLN("tcp_accept failed");
			}
			return NULL;
		}
		setup_client_kernelrw(&sock);
		if (tcp_close_connection(&sock)) {
			LOG_PRINTLN("tcp_close_connection failed");
		}
	}
	return NULL;
}
