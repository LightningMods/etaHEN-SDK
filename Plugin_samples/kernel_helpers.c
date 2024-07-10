/*****************************************************
 * PS5 SDK - Kernel helpers
 * Implements kernel hacking API for doing kernel read/
 * write.
 ****************************************************/

#include <ps5/kernel.h>

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ps5/libkernel.h>

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
kernel_copyin(const void *uaddr, unsigned long kaddr, unsigned long len) {
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
kernel_copyout(unsigned long kaddr, void *uaddr, unsigned long len) {
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
