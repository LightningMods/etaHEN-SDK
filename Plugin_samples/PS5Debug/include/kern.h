#ifndef _KERN_H
#define _KERN_H

#include "protocol.h"
#include "net.h"

/**
 * public constants.
 **/
static unsigned long KERNEL_ADDRESS_DATA_BASE      = 0;
static unsigned long KERNEL_ADDRESS_ALLPROC        = 0;
static unsigned long KERNEL_ADDRESS_PRISON0        = 0;
static unsigned long KERNEL_ADDRESS_ROOTVNODE      = 0;
static unsigned long KERNEL_ADDRESS_SECURITY_FLAGS = 0;
static unsigned long KERNEL_ADDRESS_UTOKEN_FLAGS   = 0;
static unsigned long KERNEL_ADDRESS_QA_FLAGS       = 0;
static unsigned long KERNEL_ADDRESS_TARGETID       = 0;

static const unsigned long KERNEL_OFFSET_PROC_P_UCRED = 0x40;
static const unsigned long KERNEL_OFFSET_PROC_P_FD    = 0x48;
static const unsigned long KERNEL_OFFSET_PROC_P_PID   = 0xBC;

static const unsigned long KERNEL_OFFSET_UCRED_CR_UID   = 0x04;
static const unsigned long KERNEL_OFFSET_UCRED_CR_RUID  = 0x08;
static const unsigned long KERNEL_OFFSET_UCRED_CR_SVUID = 0x0C;
static const unsigned long KERNEL_OFFSET_UCRED_CR_RGID  = 0x14;
static const unsigned long KERNEL_OFFSET_UCRED_CR_SVGID = 0x18;

static const unsigned long KERNEL_OFFSET_UCRED_CR_SCEAUTHID = 0x58;
static const unsigned long KERNEL_OFFSET_UCRED_CR_SCECAPS   = 0x60;
static const unsigned long KERNEL_OFFSET_UCRED_CR_SCEATTRS  = 0x83;

static const unsigned long KERNEL_OFFSET_FILEDESC_FD_RDIR = 0x10;
static const unsigned long KERNEL_OFFSET_FILEDESC_FD_JDIR = 0x18;

int kern_base_handle(int fd, struct cmd_packet *packet);
int kern_read_handle(int fd, struct cmd_packet *packet);
int kern_write_handle(int fd, struct cmd_packet *packet);

int kern_handle(int fd, struct cmd_packet *packet);
int kernel_set_ucred_authid(int pid, unsigned long authid);
int kernel_get_ucred_caps(int pid, unsigned char caps[16]);
int kernel_set_ucred_caps(int pid, unsigned char caps[16]);
unsigned long kernel_get_ucred_authid(int pid);
unsigned long kernel_get_proc(int pid);
unsigned long kernel_get_proc_ucred(int pid);
int kernel_copyin_ret(const void *uaddr, unsigned long kaddr, unsigned long len);
int kernel_copyout_ret(unsigned long kaddr, void *uaddr, unsigned long len);
#endif