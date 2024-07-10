#ifndef _PROCESS_UTILS_H
#define _PROCESS_UTILS_H
#include <stdint.h>
#include <stdio.h>
#include "tracer.h"

#define PROC_FD_OFFSET 0x48
#define PROC_SHARED_OBJECT_OFFSET 0x3e8
#define PROC_VMSPACE_OFFSET 0x200
#define PROC_TITLE_ID_OFFSET 0x470
#define PROC_CONTENT_ID_OFFSET 0x4C4
#define PROC_PATH_OFFSET 0x5BC

#define VMSPACE_ROOT_ENTRY 0x08
#define VMSPACE_NUM_ENTRIES 0x1A8

#define VMSPACE_ENTRY_NEXT_ENTRY 0x08
#define VMSPACE_ENTRY_START 0x20
#define VMSPACE_ENTRY_END 0x28
#define VMSPACE_ENTRY_OFFSET 0x58
#define VMSPACE_ENTRY_PROT 0x64
#define VMSPACE_ENTRY_MAX_PROT 0x66
#define VMSPACE_ENTRY_NAME 0x142

#define SHARED_LIB_IMAGEBASE_OFFSET 0x30

#define PROC_SELFINFO_NAME_OFFSET 0x59C
#define PROC_SELFINFO_NAME_SIZE 32

struct proc_list_entry {
    char p_comm[32];
    int pid;
}  __attribute__((packed));

uintptr_t shared_lib_get_imagebase(uintptr_t lib);
uintptr_t shared_object_get_eboot(uintptr_t obj);
uintptr_t proc_get_shared_object(uintptr_t proc);
uintptr_t proc_get_eboot(uintptr_t proc);
uintptr_t proc_get_eboot(uintptr_t proc);
uintptr_t proc_get_fd(uintptr_t proc);
uintptr_t proc_get_next(uintptr_t proc);
int proc_get_pid(uintptr_t proc);
uintptr_t get_current_proc(void);
void proc_get_path(uintptr_t proc, char* buf);
void proc_get_content_id(uintptr_t proc, char* buf);
void proc_get_title_id(uintptr_t proc, char* buf);
void proc_get_name(uintptr_t proc, char name[PROC_SELFINFO_NAME_SIZE]);
uintptr_t shared_object_get_lib(uintptr_t obj, int handle);
uintptr_t shared_lib_get_metadata(uintptr_t lib);
uintptr_t shared_lib_get_address(uintptr_t lib, const char *sym_nid);
uintptr_t get_proc(int target_pid);
uintptr_t proc_get_lib(uintptr_t proc, int handle);
uintptr_t proc_get_vmspace(uintptr_t proc);
uintptr_t vmspace_get_root_entry(uintptr_t vmspace);
uint32_t vmspace_get_num_entries(uintptr_t vmspace);
uintptr_t vmspace_entry_get_next_entry(uintptr_t entry);
uintptr_t vmspace_entry_get_start(uintptr_t entry);
uintptr_t vmspace_entry_get_end(uintptr_t entry);
uintptr_t vmspace_entry_get_offset(uintptr_t entry);
uint16_t vmspace_entry_get_max_prot(uintptr_t entry);
uint16_t vmspace_entry_get_prot(uintptr_t entry);
void vmspace_entry_get_name(uintptr_t entry, char name[PROC_SELFINFO_NAME_SIZE]);
int sys_proc_list(struct proc_list_entry *procs, uint64_t *num);
uintptr_t sys_proc_alloc(tracer_t* tracer, int pid, uintptr_t length);
uintptr_t sys_proc_free(tracer_t* tracer, int pid, uintptr_t address, uintptr_t length);
int sys_proc_protect(int pid, uint64_t address, int prot);
int sys_proc_protect_by_name(int pid, const char* name, int prot);
uintptr_t proc_get_ucred(uintptr_t proc);

#endif