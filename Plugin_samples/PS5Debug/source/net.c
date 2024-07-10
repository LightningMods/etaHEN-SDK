#include <sys/syscall.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <unistd.h>
#include "net.h"
#include <sys/errno.h>

#define	EAGAIN		35		/* Resource temporarily unavailable */
#define	EWOULDBLOCK	EAGAIN		/* Operation would block */

int net_select(int fd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    return syscall(93, fd, readfds, writefds, exceptfds, timeout);
}

int net_send_data(int fd, void *data, int length) {
    int left = length;
    int offset = 0;
    int sent = 0;

    errno = 0;

    while (left > 0) {
        if (left > NET_MAX_LENGTH) {
            sent = write(fd, (char*)(data )+ offset, NET_MAX_LENGTH);
        } else {
            sent = write(fd, (char*)(data )+ offset, left);
        }

        if (sent <= 0) {
            if(errno && errno != EWOULDBLOCK) {
                return sent;
            }
        } else {
            offset += sent;
            left -= sent;
        }
    }

    return offset;
}

int net_recv_data(int fd, void *data, int length, int force) {
    int left = length;
    int offset = 0;
    int recv = 0;

    errno = 0;

    while (left > 0) {
        if (left > NET_MAX_LENGTH) {
            recv = read(fd,  (char*)(data) + offset, NET_MAX_LENGTH);
        } else {
            recv = read(fd,  (char*)(data) + offset, left);
        }

        if (recv <= 0) {
            if (force) {
                if(errno && errno != EWOULDBLOCK) {
                    return recv;
                }
            } else {
                return offset;
            }
        } else {
            offset += recv;
            left -= recv;
        }
    }

    return offset;
}

int net_send_status(int fd, uint32_t status) {
    uint32_t d = status;

    return net_send_data(fd, &d, sizeof(uint32_t));
}