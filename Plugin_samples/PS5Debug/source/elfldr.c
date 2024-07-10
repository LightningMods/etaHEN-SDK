// Modified version of https://github.com/john-tornblom/ps5-payload-sdk/tree/master/samples/ptrace_elfldr
// Credits to John Tornblom
// This has some problems when loading elfs into a game process
// For example on Cold War, if you inject in the main manu it will soft lock the game, not sure why. Should probably be swapped out with a elf loader geared torwards games.

#include <elf.h>
#include <sys/mman.h>
#include <ps5/kernel.h>
#include <string.h>
#include "tracer.h"
#include "process_utils.h"
#include "mdbg.h"

#define PAGE_LENGTH 0x4000

#define ROUND_PG(x) (((x) + (PAGE_LENGTH - 1)) & ~(PAGE_LENGTH - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_LENGTH - 1))

#define PFLAGS(x) ((((x) & PF_R) ? PROT_READ : 0) |		\
		   (((x) & PF_W) ? PROT_WRITE : 0) |		\
		   (((x) & PF_X) ? PROT_EXEC : 0))


static intptr_t elfldr_load(tracer_t* tracer, uint8_t *elf, size_t size) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
    Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
    Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

    intptr_t base_addr = -1;
    size_t base_size = 0;

    size_t min_vaddr = SIZE_MAX;
    size_t max_vaddr = 0;

    int error = 0;

    // Sanity check, we only support 64bit ELFs.
    if(ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
      ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3 ||
      ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
      ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
      return -1;
    }

    // Compute size of virtual memory region.
    for(int i=0; i<ehdr->e_phnum; i++) {
      if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
        continue;
      }

      if(phdr[i].p_vaddr < min_vaddr) {
        min_vaddr = phdr[i].p_vaddr;
      }

      if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
        max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
      }
    }

    min_vaddr = TRUNC_PG(min_vaddr);
    max_vaddr = ROUND_PG(max_vaddr);
    base_size = max_vaddr - min_vaddr;

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if(ehdr->e_type == ET_DYN) {
      base_addr = 0;
    } else if(ehdr->e_type == ET_EXEC) {
      base_addr = min_vaddr;
      flags |= MAP_FIXED;
    } else {
      return -1;
    }

    // Reserve an address space of sufficient size.
    if((base_addr=tracer_mmap(tracer, base_addr, base_size, PROT_NONE, flags, -1, 0)) == -1) {
        tracer_perror(tracer, "mmap");
        return -1;
    }

    // Commit segments to reserved address space.
    for(int i=0; i<ehdr->e_phnum; i++) {
      size_t aligned_memsz = ROUND_PG(phdr[i].p_memsz);
      intptr_t addr = base_addr + phdr[i].p_vaddr;
      int alias_fd = -1;
      int shm_fd = -1;

      if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
        continue;
      }

      if(phdr[i].p_flags & PF_X) {
        if((shm_fd=tracer_jitshm_create(tracer, 0, aligned_memsz, PROT_WRITE | PFLAGS(phdr[i].p_flags))) < 0) {
            tracer_perror(tracer, "jitshm_create");
            error = 1;
            break;
        }

        if((addr=tracer_mmap(tracer, addr, aligned_memsz, PFLAGS(phdr[i].p_flags), MAP_FIXED | MAP_SHARED, shm_fd, 0)) == -1) {
            tracer_perror(tracer, "mmap");
            error = 1;
            break;
        }

        if((alias_fd=tracer_jitshm_alias(tracer, shm_fd, PROT_WRITE | PROT_READ)) < 0) {
            tracer_perror(tracer, "jitshm_alias");
            error = 1;
            break;
        }

        if((addr=tracer_mmap(tracer, 0, aligned_memsz, PROT_WRITE | PROT_READ, MAP_SHARED, alias_fd, 0)) == -1) {
            tracer_perror(tracer, "mmap");
            error = 1;
            break;
        }

        userland_copyin(tracer->pid, elf + phdr[i].p_offset, addr, phdr[i].p_memsz);

        tracer_munmap(tracer, addr, aligned_memsz);
        tracer_close(tracer, alias_fd);
        tracer_close(tracer, shm_fd);
      } else {
        if((addr=tracer_mmap(tracer, addr, aligned_memsz, PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
            tracer_perror(tracer, "mmap");
            error = 1;
            break;
        }
        userland_copyin(tracer->pid, elf + phdr[i].p_offset, addr, phdr[i].p_memsz);
      }
    }

    // Relocate positional independent symbols.
    for(int i=0; i<ehdr->e_shnum && !error; i++) {
      if(shdr[i].sh_type != SHT_RELA) {
        continue;
      }

      Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
      for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {
        if(ELF64_R_TYPE(rela[j].r_info) == R_X86_64_RELATIVE) {
            intptr_t value_addr = (base_addr + rela[j].r_offset);
            intptr_t value = base_addr + rela[j].r_addend;
            userland_copyin(tracer->pid, &value, value_addr, sizeof(Elf64_Addr));
        }
      }
    }

    // Set protection bits on mapped segments.
    for(int i=0; i<ehdr->e_phnum && !error; i++) {
      size_t aligned_memsz = ROUND_PG(phdr[i].p_memsz);
      intptr_t addr = base_addr + phdr[i].p_vaddr;

      if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
        continue;
      }

      if(tracer_mprotect(tracer, addr, aligned_memsz, PFLAGS(phdr[i].p_flags))) {
        tracer_perror(tracer, "mprotect");
        error = 1;
        break;
      }
    }

    if(error) {
      return -1;
    } else {
      return base_addr + ehdr->e_entry;
    }
}


static intptr_t elfldr_args(tracer_t* tracer) {
    intptr_t buf;

    if((buf=tracer_mmap(tracer, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
      tracer_perror(tracer, "mmap");
      return 0;
    }

    uintptr_t proc = get_proc(tracer->pid);
    uintptr_t libKernel = proc_get_lib(proc, 0x2001);
    uintptr_t eboot = proc_get_eboot(proc);

    intptr_t args       = buf;
    intptr_t dlsym      = shared_lib_get_address(libKernel, "LwG8g3niqwA");
    intptr_t imageBase  = shared_lib_get_imagebase(eboot);

    userland_copyin(tracer->pid, &dlsym, args + 0x00, sizeof(uintptr_t));
    userland_copyin(tracer->pid, &imageBase, args + 0x08, sizeof(uintptr_t));
    
    return args;
}


int inject_elf(int pid, uint8_t *elf, size_t size) {
    uint8_t caps[16];
    uint8_t buf[16];
    struct reg r;

    if(kernel_get_ucred_caps(pid, caps)) {
        perror("kernel_get_ucred_caps");
        return -1;
    }

    memset(buf, 0xff, sizeof(buf));
    if(kernel_set_ucred_caps(pid, buf)) {
        perror("kernel_set_ucred_caps");
        return -1;
    }
  
    tracer_t tracer;
    if (tracer_init(&tracer, pid) < 0) {
        return -1;
    }

    if(tracer_get_registers(&tracer, &r)) {
        tracer_perror(&tracer, "pt_getregs");
        tracer_finalize(&tracer);
        return -1;
    }

    if(!(r.r_rdi=elfldr_args(&tracer))) {
        tracer_finalize(&tracer);
        return -1;
    }

    if(!(r.r_rip=elfldr_load(&tracer, elf, size))) {
        tracer_finalize(&tracer);
        return -1;
    }

    kernel_set_ucred_caps(pid, caps);

    if(tracer_set_registers(&tracer, &r)) {
        tracer_perror(&tracer, "pt_setregs");
        tracer_finalize(&tracer);
        return -1;
    }

    tracer_finalize(&tracer);

    return r.r_rip;
}