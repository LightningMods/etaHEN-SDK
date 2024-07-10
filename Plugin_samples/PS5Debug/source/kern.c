#include <ps5/kernel.h>

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ps5/libkernel.h>
#include "kern.h"

void free(void* ptr);
void*  pfmalloc(size_t sz);
void * memset ( void * ptr, int value, size_t num );

// Store necessary sockets/pipe for corruption.
int _master_sock;
int _victim_sock;
int _rw_pipe[2];
uint64_t _pipe_addr;

// Arguments passed by way of entrypoint arguments.
void kernel_init_rw(int master_sock, int victim_sock, int *_rw_pipe, uint64_t pipe_addr)
{
	_master_sock = master_sock;
	_victim_sock = victim_sock;
	_rw_pipe[0]  = _rw_pipe[0];
	_rw_pipe[1]  = _rw_pipe[1];
	_pipe_addr   = pipe_addr;
}

// Internal kwrite function - not friendly, only for setting up better primitives.
int kwrite(uint64_t addr, uint64_t *data) {
	uint64_t victim_buf[3];

        // sanity check for invalid kernel pointers
  	if(!(addr & 0xffff000000000000)) {
          return -1;
        }

	victim_buf[0] = addr;
	victim_buf[1] = 0;
	victim_buf[2] = 0;

	if(setsockopt(_master_sock, IPPROTO_IPV6, IPV6_PKTINFO, victim_buf, 0x14) < 0)
           return -1;
	if(setsockopt(_victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, data, 0x14) < 0)
           return -1;

        return 0;
}

int
kernel_copyin_ret(const void *uaddr, unsigned long kaddr, unsigned long len) {
  unsigned long write_buf[3];

  if(!kaddr || !uaddr || !len) {
    return -1;
  }

  // Set pipe flags
  write_buf[0] = 0;
  write_buf[1] = 0x4000000000000000;
  write_buf[2] = 0;
  if(kwrite(_pipe_addr, (uint64_t*) &write_buf)) {
    return -1;
  }

  // Set pipe data addr
  write_buf[0] = kaddr;
  write_buf[1] = 0;
  write_buf[2] = 0;
  if(kwrite(_pipe_addr + 0x10, (uint64_t*) &write_buf)) {
    return -1;
  }

  // Perform write across pipe
  if(_write(_rw_pipe[1], uaddr, len) < 0) {
    return -1;
  }

  return 0;
}


int
kernel_copyout_ret(unsigned long kaddr, void *uaddr, unsigned long len) {
  unsigned long write_buf[3];

  if(!kaddr || !uaddr || !len) {
    return -1;
  }

  // Set pipe flags
  write_buf[0] = 0x4000000040000000;
  write_buf[1] = 0x4000000000000000;
  write_buf[2] = 0;
  if(kwrite(_pipe_addr, (uint64_t*) &write_buf)) {
    return -1;
  }

  // Set pipe data addr
  write_buf[0] = kaddr;
  write_buf[1] = 0;
  write_buf[2] = 0;
  if(kwrite(_pipe_addr + 0x10, (uint64_t*) &write_buf)) {
    return -1;
  }

  // Perform read across pipe
  if(_read( _rw_pipe[0], uaddr, len) < 0) {
    return -1;
  }

  return 0;
}

int
kernel_set_ucred_caps(int pid, unsigned char caps[16]) {
  unsigned long ucred = 0;

  if(!(ucred=kernel_get_proc_ucred(pid))) {
    return -1;
  }

  if(kernel_copyin_ret(caps, ucred + KERNEL_OFFSET_UCRED_CR_SCECAPS, 16)) {
    return -1;
  }

  return 0;
}



unsigned long
kernel_get_proc_ucred(int pid) {
  unsigned long proc = 0;
  unsigned long ucred = 0;

  if(!(proc=kernel_get_proc(pid))) {
    return 0;
  }

  if(kernel_copyout_ret(proc + KERNEL_OFFSET_PROC_P_UCRED, &ucred,
		    sizeof(ucred))) {
    return 0;
  }

  return ucred;
}

unsigned long
kernel_get_proc(int pid) {
  unsigned int other_pid = 0;
  unsigned long addr = 0;
  unsigned long next = 0;

  if(kernel_copyout_ret(KERNEL_ADDRESS_ALLPROC, &addr, sizeof(addr))) {
    return 0;
  }

  while(addr) {
    if(kernel_copyout_ret(addr + KERNEL_OFFSET_PROC_P_PID, &other_pid,
		      sizeof(other_pid))) {
      return 0;
    }

    if(pid == other_pid) {
      break;
    }

    if(kernel_copyout_ret(addr, &next, sizeof(next))) {
      return 0;
    }

    addr = next;
  }

  return addr;
}

int
kernel_get_ucred_caps(int pid, unsigned char caps[16]) {
  unsigned long ucred = 0;

  if(!(ucred=kernel_get_proc_ucred(pid))) {
    return -1;
  }

  if(kernel_copyout_ret(ucred + KERNEL_OFFSET_UCRED_CR_SCECAPS, caps, 16)) {
    return -1;
  }

  return 0;
}

unsigned long
kernel_get_ucred_authid(int pid) {
  unsigned long authid = 0;
  unsigned long ucred = 0;

  if(!(ucred=kernel_get_proc_ucred(pid))) {
    return 0;
  }

  if(kernel_copyout_ret(ucred + KERNEL_OFFSET_UCRED_CR_SCEAUTHID, &authid,
		    sizeof(authid))) {
    return 0;
  }

  return authid;
}

int
kernel_set_ucred_authid(int pid, unsigned long authid) {
  unsigned long ucred = 0;

  if(!(ucred=kernel_get_proc_ucred(pid))) {
    return -1;
  }

  if(kernel_copyin_ret(&authid, ucred + KERNEL_OFFSET_UCRED_CR_SCEAUTHID,
		   sizeof(authid))) {
    return -1;
  }

  return 0;
}


int kern_base_handle(int fd, struct cmd_packet *packet) {
    uint64_t kernbase = KERNEL_ADDRESS_DATA_BASE;


	net_send_status(fd, CMD_SUCCESS);
	net_send_data(fd, &kernbase, sizeof(uint64_t));

	return 0;
}

int kern_read_handle(int fd, struct cmd_packet *packet) {
    struct cmd_kern_read_packet *rp;
	void *data;
	uint64_t left;
	uint64_t address;

	rp = (struct cmd_kern_read_packet *)packet->data;

	if(rp) {
		data = pfmalloc(NET_MAX_LENGTH);
		if(!data) {
			net_send_status(fd, CMD_DATA_NULL);
			return 1;
		}

		net_send_status(fd, CMD_SUCCESS);

		left = rp->length;
		address = rp->address;

		while (left > 0) {
			(void)memset(data, 0, NET_MAX_LENGTH);

			if (left > NET_MAX_LENGTH) {
                kernel_copyout_ret(address, data, NET_MAX_LENGTH);
				net_send_data(fd, data, NET_MAX_LENGTH);

				address += NET_MAX_LENGTH;
				left -= NET_MAX_LENGTH;
			}
			else {
                kernel_copyout_ret(address, data, left);
				net_send_data(fd, data, left);

				address += left;
				left -= left;
			}
		}

		free(data);
		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);
	return 1;
}

int kern_write_handle(int fd, struct cmd_packet *packet) {
    struct cmd_kern_write_packet *wp;
	void *data;
	uint64_t left;
	uint64_t address;

	wp = (struct cmd_kern_write_packet *)packet->data;

	if(wp) {
		data = pfmalloc(NET_MAX_LENGTH);
		if(!data) {
			net_send_status(fd, CMD_DATA_NULL);
			return 1;
		}

		net_send_status(fd, CMD_SUCCESS);

		left = wp->length;
		address = wp->address;

		while (left > 0) {
			if (left > NET_MAX_LENGTH) {
				net_recv_data(fd, data, NET_MAX_LENGTH, 1);
                kernel_copyin_ret(data, address, NET_MAX_LENGTH);

				address += NET_MAX_LENGTH;
				left -= NET_MAX_LENGTH;
			}
			else {
				net_recv_data(fd, data, left, 1);
                kernel_copyin_ret(data, address, left);

				address += left;
				left -= left;
			}
		}

		net_send_status(fd, CMD_SUCCESS);

		free(data);
		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);
	return 1;
}

int kern_handle(int fd, struct cmd_packet *packet) {
    switch(packet->cmd) {
        case CMD_KERN_BASE:
            return kern_base_handle(fd, packet);
        case CMD_KERN_READ:
            return kern_read_handle(fd, packet);
        case CMD_KERN_WRITE:
            return kern_write_handle(fd, packet);
    }

    return 1;
}