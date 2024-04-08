#include "elfldr.h"
#include "libs.h"
#include "memory.h"
#include "module.h"
#include "nid_resolver/resolver.h"
#include "nid_resolver/sysmodules.h"
#include "proc.h"
#include "rtld.h"
#include "tracer.h"

#include <elf.h>
#include <netinet/in.h>
#include <ps5/dlsym.h>
#include <ps5/payload_main.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/elf64.h>
#include <sys/elf_common.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>



void* malloc(size_t size);
void free(void* ptr);

#define PAGE_LENGTH 0x4000
#define SIZE_ALIGN(size, alignment) (((size) + ((alignment) - 1)) & ~((alignment) - 1))
#define STACK_ALIGN 0x10

#ifndef IPV6_2292PKTOPTIONS
#define IPV6_2292PKTOPTIONS 25
#endif

#define FILEDESCENT_LENGTH 0x30
#define LIB_SYSTEM_SERVICE_ID 0x80000010

#define PROT_GPU_READ 0x10
#define PROT_GPU_WRITE 0x20

#define MMAP_TEXT_FLAGS MAP_FIXED | MAP_SHARED
#define MMAP_DATA_FLAGS MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE

#define STARTS_WITH(lib, s) (strncmp(lib, (s), strlen(s)) == 0)
#define LOOKUP_SYMBOL(resolver, sym) resolver_lookup_symbol(resolver, sym, strlen(sym))
#define GET_LIB(pid, lib) get_module_handle(pid, lib, strlen(lib))


static inline size_t page_align(size_t length) {
	return SIZE_ALIGN(length, PAGE_LENGTH);
}

static const Elf64_Ehdr *get_elf_header(const elf_loader_t *restrict self) {
	return (Elf64_Ehdr *)self->buf;
}

static const Elf64_Phdr *get_program_headers(const elf_loader_t *restrict self) {
	return (Elf64_Phdr *) (self->buf + get_elf_header(self)->e_phoff);
}

static const Elf64_Phdr *get_text_header(elf_loader_t *self) {
	const Elf64_Phdr *const restrict phdrs = get_program_headers(self);
	if (self ->text_index != -1) {
		return phdrs + self->text_index;
	}

	const Elf64_Ehdr *const restrict elf = get_elf_header(self);
	for (ssize_t i = 0; i < elf->e_phnum; i++) {
		if (phdrs[i].p_flags & PF_X) {
			self->text_index = i;
			return phdrs + self->text_index;
		}
	}

	return NULL;
}

static const Elf64_Phdr *get_phdr_containing(elf_loader_t *restrict self, uintptr_t addr) {
	const Elf64_Phdr *const restrict phdrs = get_program_headers(self);
	const Elf64_Ehdr *const restrict elf = get_elf_header(self);
	for (ssize_t i = 0; i < elf->e_phnum; i++) {
		if (addr >= phdrs[i].p_paddr && addr < (phdrs[i].p_paddr+phdrs[i].p_filesz)) {
			return phdrs + i;
		}
	}
	return NULL;
}

static void *to_file_offset(elf_loader_t *restrict self, uintptr_t addr) {
	const Elf64_Phdr *const restrict phdr = get_phdr_containing(self, addr);
	if (phdr == NULL) {
		printf("phdr containing 0x%08llx not found\n", addr);
		return (void *) addr; // NOLINT(performance-no-int-to-ptr)
	}
	return (void *) (addr - phdr->p_paddr + phdr->p_offset);// NOLINT(performance-no-int-to-ptr)
}

static void *faddr(elf_loader_t *restrict self, uintptr_t addr) {
	return self->buf + (uintptr_t)to_file_offset(self, addr);
}

static uintptr_t elf_get_proc(elf_loader_t *restrict self) {
	if (self->proc != 0) {
		return self->proc;
	}
	self->proc = get_proc(self->pid);
	return self->proc;
}

static const Elf64_Dyn *get_dynamic_table(elf_loader_t *restrict self) {
	const Elf64_Phdr *const restrict phdrs = get_program_headers(self);
	if (self->dynamic_index >= 0) {
		return (Elf64_Dyn *)(self->buf + phdrs[self->dynamic_index].p_offset);
	}

	const Elf64_Ehdr *const restrict elf = get_elf_header(self);
	for (size_t i = 0; i < elf->e_phnum; i++) {
		if (phdrs[i].p_type == PT_DYNAMIC) {
			self->dynamic_index = (ssize_t)i;
			return (Elf64_Dyn *)(self->buf + phdrs[i].p_offset);
		}
	}

	return NULL;
}

static uintptr_t to_virtual_address(elf_loader_t *restrict self, uintptr_t addr) {
	const Elf64_Phdr *restrict text = get_text_header(self);
	if (addr >= text->p_vaddr)  {
		addr -= text->p_vaddr + text->p_offset;
	}
	return self->imagebase + addr;
}

static bool is_loadable(const Elf64_Phdr *phdr) {
	return phdr->p_type == PT_LOAD || phdr->p_type == PT_GNU_EH_FRAME;
}

static size_t get_total_load_size(elf_loader_t *restrict self) {
	const Elf64_Ehdr *const restrict elf = get_elf_header(self);
	const Elf64_Phdr *const restrict begin = get_program_headers(self);
	const Elf64_Phdr *const restrict end = begin + elf->e_phnum;
	size_t size = 0;
	for (const Elf64_Phdr *restrict it = begin; it != end; it++) {
		if (is_loadable(it)) {
			if (it->p_align != PAGE_LENGTH) {
				printf("warning phdr with p_paddr 0x%08llx has alignment 0x%08llx\n", it->p_paddr, it->p_align);
			}
			size += SIZE_ALIGN(it->p_memsz, it->p_align);
		}
	}
	return size;
}

static int add_library(elf_loader_t *restrict self, int64_t handle) {
	const uintptr_t proc = elf_get_proc(self);
	const uintptr_t lib = proc_get_lib(proc, (int)handle);
	if (lib == 0) {
		printf("failed to get lib for handle 0x%lx\n", handle);
		return -1;
	}

	const uintptr_t meta = shared_lib_get_metadata(lib);
	if (meta == 0) {
	    printf("failed to get metadata for handle 0x%lx\n", handle);
		return -1;
	}

	const uintptr_t imagebase = shared_lib_get_imagebase(lib);

	return resolver_add_library_metadata(&self->resolver, imagebase, meta);
}

static int64_t load_library(elf_loader_t *restrict self, uintptr_t id_loader, uintptr_t name_loader, uintptr_t mem, const char *lib, size_t length) {
	uint32_t id = get_sysmodule_id(lib, length);
	if (id != 0) {
		if ((int64_t)tracer_call(&self->tracer, id_loader, id, 0, 0, 0, 0, 0) == -1) {
			printf("failed to load lib %s\n", lib);
			//return -1;
		}
	} else {
		userland_copyin(self->pid, lib, mem, length);
		userland_copyin(self->pid, ".sprx", mem + length, sizeof(".sprx"));
		if ((int64_t)tracer_call(&self->tracer, name_loader, mem, 0, 0, 0, 0, 0) == -1) {
			printf("failed to load lib %s\n", lib);
			//return -1;
		}
	}
	return get_module_handle(self->pid, lib, length);
}

static bool load_libraries(elf_loader_t *restrict self) {
	const uintptr_t name_loader = LOOKUP_SYMBOL(&self->resolver, "sceSysmoduleLoadModuleByNameInternal");
	const uintptr_t id_loader = LOOKUP_SYMBOL(&self->resolver, "sceSysmoduleLoadModuleInternal");
	if (name_loader == 0) {
		puts("failed to resolve sceSysmoduleLoadModuleByNameInternal");
		return false;
	}
	if (id_loader == 0) {
		puts("failed to resolve sceSysmoduleLoadModuleInternal");
		return false;
	}
	const uintptr_t mem = tracer_mmap(&self->tracer, 0, PAGE_LENGTH, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if ((int64_t)mem == -1) {
		tracer_perror(&self->tracer, "load_libraries tracer_mmap");
		return false;
	}

	const Elf64_Dyn *restrict dyntab = get_dynamic_table(self);
	for (const Elf64_Dyn *restrict dyn = dyntab; dyn->d_tag != DT_NULL; dyn++) {
		if (dyn->d_tag != DT_NEEDED) {
			continue;
		}

		const char *lib = self->strtab + dyn->d_un.d_val;
		if (STARTS_WITH(lib, "libkernel")) {
			continue;
		}
		if (STARTS_WITH(lib, "libc.") || STARTS_WITH(lib, "libSceLibcInternal")) {
			continue;
		}
		const char *ext = strrchr(lib, '.');
		size_t length = ext != NULL ? ext - lib : strlen(lib);
		int64_t handle = load_library(self, id_loader, name_loader, mem, lib, length);
		//printf("library %s handle 0x%llx\n", lib, handle);
		if (handle < 0 || add_library(self, handle) < 0) {
			printf("failed to load library %s\n", lib);
			if (tracer_munmap(&self->tracer, mem, PAGE_LENGTH) == -1) {
				tracer_perror(&self->tracer, "load_libraries tracer_munmap");
			}
			return false;
		}
	}

	if (tracer_munmap(&self->tracer, mem, PAGE_LENGTH) == -1) {
		tracer_perror(&self->tracer, "load_libraries tracer_munmap");
		// it's a memory leak but we did successfully load the libraries
	}

	return true;
}

void process_dynamic_table(elf_loader_t *restrict self) {
	const Elf64_Dyn *restrict dyntab = get_dynamic_table(self);
	for (const Elf64_Dyn *restrict dyn = dyntab; dyn->d_tag != DT_NULL; dyn++) {
		switch (dyn->d_tag) {
			case DT_RELA:
				self->reltab = (Elf64_Rela *)faddr(self, dyn->d_un.d_ptr);
				break;
			case DT_RELASZ:
				self->reltab_size = dyn->d_un.d_val / sizeof(Elf64_Rela);
				break;
			case DT_JMPREL:
				self->plttab = (Elf64_Rela *)faddr(self, dyn->d_un.d_ptr);
				break;
			case DT_PLTRELSZ:
				self->plttab_size = dyn->d_un.d_val / sizeof(Elf64_Rela);
				break;
			case DT_SYMTAB:
				self->symtab = (Elf64_Sym *)faddr(self, dyn->d_un.d_ptr);
				self->symtab_size = dyn->d_un.d_val / sizeof(Elf64_Sym);
				break;
			case DT_STRTAB:
				self->strtab = (const char *)faddr(self, dyn->d_un.d_ptr);
				break;
			default:
				break;
		}
	}
}

static size_t get_text_size(elf_loader_t *restrict self) {
	return page_align(get_text_header(self)->p_memsz);
}


static int to_mmap_prot(const Elf64_Phdr *phdr) {
	int res = 0;
	if (phdr->p_flags & PF_X) {
		res |= PROT_EXEC;
	}
	if (phdr->p_flags & PF_R) {
		res |= PROT_READ | PROT_GPU_READ;
	}
	if (phdr->p_flags & PF_W) {
		res |= PROT_WRITE | PROT_GPU_WRITE;
	}
	return res;
}

static bool map_elf_memory(elf_loader_t *restrict self) {
	const size_t text_size = get_text_size(self);
	const size_t total_size = get_total_load_size(self);

	uintptr_t mem = tracer_mmap(&self->tracer, 0, total_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if ((int64_t)mem == -1) {
		tracer_perror(&self->tracer, "map_elf_memory tracer_mmap");
		return false;
	}

	self->imagebase = mem;

	if (tracer_munmap(&self->tracer, mem, total_size) == -1) {
		tracer_perror(&self->tracer, "map_elf_memory tracer_munmap");
		return false;
	}

	int jit = tracer_jitshm_create(&self->tracer, 0, text_size, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (jit == -1) {
		tracer_perror(&self->tracer, "map_elf_memory tracer_jitshm_create");
		return false;
	}

	const Elf64_Ehdr *restrict elf = get_elf_header(self);
	const Elf64_Phdr *restrict phdrs = get_program_headers(self);

	for (ssize_t i = 0; i < elf->e_phnum; i++) {
		if (!is_loadable(phdrs + i)) {
			continue;
		}

		uintptr_t res;
		const uintptr_t addr = to_virtual_address(self, phdrs[i].p_paddr);
		const size_t size = page_align(phdrs[i].p_memsz);
		const int prot = to_mmap_prot(phdrs + i);
		const int flags = i == self->text_index ? MMAP_TEXT_FLAGS : MMAP_DATA_FLAGS;
		const int fd = i == self->text_index ? jit : -1;

		res = tracer_mmap(&self->tracer, addr, size, prot, flags, fd, 0);
		if ((int64_t)res == -1) {
			tracer_perror(&self->tracer, "map_elf_memory tracer_mmap");
			return false;
		}

		if (res != addr) {
			printf("tracer_mmap did not give the requested address requested 0x%08llx received 0x%08llx\n", addr, res);
			return false;
		}
	}

	return true;
}

static uintptr_t get_symbol_address(elf_loader_t *restrict self, const Elf64_Rela *restrict rel) {
	const char *name = self->strtab + self->symtab[ELF64_R_SYM(rel->r_info)].st_name;
	const size_t length = strlen(name);
	uintptr_t libsym = resolver_lookup_symbol(&self->resolver, name, length);
	if (libsym == 0) {
		printf("failed to find library symbol %s\n", name);
		return 0;
	}
	return libsym;
}

static bool elf_process_plt_relocations(elf_loader_t *restrict self) {
	for (size_t i = 0; i < self->plttab_size; i++) {
		const Elf64_Rela *restrict plt = self->plttab + i;
		if ((ELF64_R_TYPE(plt->r_info)) != R_X86_64_JMP_SLOT) {
			const Elf64_Sym *sym = self->symtab + ELF64_R_SYM(plt->r_info);
			const char *name = self->strtab + sym->st_name;
			unsigned int type = ELF64_R_TYPE(plt->r_info);
			printf("unexpected relocation type %u for symbol %s\n", type, name);
			return false;
		}

		uintptr_t libsym = get_symbol_address(self, plt);
		if (libsym == 0) {
			return false;
		}
		*(uintptr_t*)(faddr(self, plt->r_offset)) = libsym;
	}

	return true;
}

static bool elf_process_rela_relocations(elf_loader_t *restrict self) {
	if (self->reltab == NULL) {
		return true;
	}
	for (size_t i = 0; i < self->reltab_size; i++) {
		const Elf64_Rela *restrict rel = self->reltab + i;
		switch (ELF64_R_TYPE(rel->r_info)) {
			case R_X86_64_64: {
				// symbol + addend
				uintptr_t libsym = get_symbol_address(self, rel);
				if (libsym == 0) {
					return false;
				}
				*(uintptr_t*)(faddr(self, rel->r_offset)) = libsym + rel->r_addend;
				break;
			}
			case R_X86_64_GLOB_DAT: {
				// symbol
				uintptr_t libsym = get_symbol_address(self, rel);
				if (libsym == 0) {
					return false;
				}
				*(uintptr_t*)(faddr(self, rel->r_offset)) = libsym;
				break;
			}
			case R_X86_64_RELATIVE: {
				// imagebase + addend
				*(uintptr_t*)(faddr(self, rel->r_offset)) = to_virtual_address(self, rel->r_addend);
				break;
			}
			case R_X86_64_JMP_SLOT: {
				// edge case where the dynamic relocation sections are merged
				uintptr_t libsym = get_symbol_address(self, rel);
				if (libsym == 0) {
					return false;
				}
				*(uintptr_t*)(faddr(self, rel->r_offset)) = libsym;
				break;
			}
			default: {
				const Elf64_Sym *sym = self->symtab + ELF64_R_SYM(rel->r_info);
				const char *name = self->strtab + sym->st_name;
				unsigned int type = ELF64_R_TYPE(rel->r_info);
				__builtin_printf("unexpected relocation type %u for symbol %s\n", type, name);
				return false;
			}
		}
	}
	return true;
}

static bool elf_process_relocations(elf_loader_t *restrict self) {
	return elf_process_plt_relocations(self) && elf_process_rela_relocations(self);
}

static int elf_resolver_init(elf_loader_t *restrict self) {
	const uintptr_t proc = get_proc(self->pid);

	if (proc == 0) {
		puts("elf_resolver_init failed to get target proc");
		return -1;
	}

	const uintptr_t libkernel = proc_get_lib(proc, LIBKERNEL_HANDLE);
	if (libkernel == 0) {
		puts("failed to get target libkernel");
	}

	const uintptr_t libc = proc_get_lib(proc, LIBC_HANDLE);
	if (libc == 0) {
		puts("failed to get target libc");
	}

	const uintptr_t libkernel_meta = shared_lib_get_metadata(libkernel);
	if (libkernel_meta == 0) {
		puts("failed to get libkernel metadata");
	}

	const uintptr_t libc_meta = shared_lib_get_metadata(libc);
	if (libc_meta == 0) {
		puts("failed to get libc metadata");
	}

	const uintptr_t libkernel_imagebase = shared_lib_get_imagebase(libkernel);
	if (libkernel_imagebase == 0) {
		puts("failed to get libkernel imagebase");
	}

	const uintptr_t libc_imagebase = shared_lib_get_imagebase(libc);
	if (libc_imagebase == 0) {
		puts("failed to get libc imagebase");
	}

	resolver_init(&self->resolver);

	resolver_add_library_metadata(&self->resolver, libkernel_imagebase, libkernel_meta);
	resolver_add_library_metadata(&self->resolver, libc_imagebase, libc_meta);

	return 0;
}

static int elf_init(elf_loader_t *restrict self, uint8_t *buf, int pid) { // NOLINT(readability-non-const-parameter)
	*self = (elf_loader_t) {
		.buf = buf,
		.text_index = -1,
		.dynamic_index = -1,
		.reltab = NULL,
		.reltab_size = 0,
		.plttab = NULL,
		.plttab_size = 0,
		.symtab = NULL,
		.strtab = NULL,
		.imagebase = 0,
		.pid = pid
	};
	int err = tracer_init(&self->tracer, self->pid);
	if (err < 0) {
		puts("elf_init tracer_init failed");
		return err;
	}
	elf_resolver_init(self);
	return 0;
}

static int elf_finalize(elf_loader_t *restrict self) {
	resolver_finalize(&self->resolver);
	int err = tracer_finalize(&self->tracer);
	if (err < 0) {
		puts("elf_finalize tracer_finalize failed");
	}
	return err;
}

static uintptr_t get_file(uintptr_t tbl, uintptr_t fd) {
	uintptr_t fp = tbl + (fd * FILEDESCENT_LENGTH) + sizeof(uintptr_t);
	uintptr_t file = 0;
	kernel_copyout(fp, &file, sizeof(file));
	return file;
}

static uintptr_t get_file_data(uintptr_t tbl, uintptr_t fd) {
	uintptr_t data = 0;
	kernel_copyout(get_file(tbl, fd), &data, sizeof(data));
	return data;
}

static uintptr_t get_fd_tbl(uintptr_t fd) {
	uintptr_t tbl = 0;
	kernel_copyout(fd, &tbl, sizeof(tbl));
	return tbl;
}

static void kwrite_uint32(uintptr_t addr, uint32_t value) {
	kernel_copyin(&value, addr, sizeof(value));
}

static void kwrite_uintptr(uintptr_t addr, uintptr_t value) {
	kernel_copyin(&value, addr, sizeof(value));
}

static uintptr_t kread_uintptr(uintptr_t addr) {
	uintptr_t res = 0;
	kernel_copyout(addr, &res, sizeof(res));
	return res;
}

static bool create_read_write_sockets(uintptr_t proc, const int *sockets) {
	// NOLINTBEGIN(readability-magic-numbers)
	uintptr_t newtbl = get_fd_tbl(proc_get_fd(proc));
	uintptr_t sock = get_file_data(newtbl, sockets[0]);
	if (sock == 0) {
		puts("create_read_write_sockets sock == 0");
		return false;
	}
	kwrite_uint32(sock, 0x100);
	uintptr_t pcb = kread_uintptr(sock + 0x18);
	if (pcb == 0) {
		puts("create_read_write_sockets master pcb == 0");
		return false;
	}
	uintptr_t master_inp6_outputopts = kread_uintptr(pcb + 0x120);
	if (master_inp6_outputopts == 0) {
		puts("create_read_write_sockets master_inp6_outputopts == 0");
		return false;
	}
	sock = get_file_data(newtbl, sockets[1]);
	if (sock == 0) {
		puts("create_read_write_sockets sock == 0");
		return false;
	}
	kwrite_uint32(sock, 0x100);
	pcb = kread_uintptr(sock + 0x18);
	if (pcb == 0) {
		puts("create_read_write_sockets victim pcb == 0");
		return false;
	}
	uintptr_t victim_inp6_outputopts = kread_uintptr(pcb + 0x120);
	if (victim_inp6_outputopts == 0) {
		puts("create_read_write_sockets victim_inp6_outputopts == 0");
		return false;
	}
	kwrite_uintptr(master_inp6_outputopts + 0x10, victim_inp6_outputopts + 0x10);
	kwrite_uint32(master_inp6_outputopts + 0xc0, 0x13370000);
	return true;
	// NOLINTEND(readability-magic-numbers)
}

typedef struct process_args {
	struct payload_args args;
	int fds[4];
	int res;
} process_args_t;

static uintptr_t setup_kernel_rw(elf_loader_t *restrict self) {

	int files[4];
	files[0] = tracer_socket(&self->tracer, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	files[1] = tracer_socket(&self->tracer, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	//printf("master socket: %d\n", files[0]);
	//printf("victim socket: %d\n", files[1]);

	if (files[0] == -1 || files[1] == -1) {
		tracer_perror(&self->tracer, "setup_kernel_rw tracer_socket");
		return 0;
	}

	if (tracer_pipe(&self->tracer, files + 2) < 0) {
		tracer_perror(&self->tracer, "setup_kernel_rw tracer_pipe");
		return 0;
	}

	//printf("rw pipes: %d, %d\n", files[2], files[3]);

	unsigned int buf[] = {20, IPPROTO_IPV6, IPV6_TCLASS, 0, 0, 0}; // NOLINT(*)

	if (tracer_setsockopt(&self->tracer, files[0], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, sizeof(buf)) == -1) {
		tracer_perror(&self->tracer, "setup_kernel_rw tracer_setsockopt master");
	}

	__builtin_memset(buf, 0, sizeof(buf));

	if (tracer_setsockopt(&self->tracer, files[1], IPPROTO_IPV6, IPV6_PKTINFO, buf, sizeof(buf) - sizeof(int)) == -1) {
		tracer_perror(&self->tracer, "setup_kernel_rw tracer_setsockopt victim");
	}

	uintptr_t proc = get_proc(self->pid);

	if (!create_read_write_sockets(proc, files)) {
		puts("failed to create kernelrw sockets");
		return 0;
	}

	uintptr_t newtbl = kread_uintptr(proc_get_fd(proc));
	const uintptr_t pipeaddr = kread_uintptr(get_file(newtbl, files[2]));

	uintptr_t malloc = LOOKUP_SYMBOL(&self->resolver, "malloc");
	if (malloc == 0) {
		puts("failed to resolve malloc");
		return 0;
	}

	// NOLINTBEGIN(performance-no-int-to-ptr)
	process_args_t *p_args = (process_args_t *)tracer_call(&self->tracer, malloc, sizeof(process_args_t), 0, 0, 0, 0, 0);
	if (p_args == 0) {
		puts("failed to allocate process args");
		return 0;
	}

	uintptr_t dlsym = LOOKUP_SYMBOL(&self->resolver, "sceKernelDlsym");
	process_args_t args = {
		.fds = {files[0], files[1], files[2], files[3]},
		.res = 0,
		.args = {
			.dlsym = (dlsym_t *)dlsym,
			.rwpipe = &p_args->fds[2],
			.rwpair = &p_args->fds[0],
			.kpipe_addr = pipeaddr,
			.kdata_base_addr = kernel_base,
			.payloadout = &p_args->res,
		},
	};

	userland_copyin(self->pid, &args, (uintptr_t)p_args, sizeof(args));
	return (uintptr_t)p_args;
	// NOLINTEND(performance-no-int-to-ptr)
}

static void elf_load(elf_loader_t *restrict self) {
	const Elf64_Ehdr *const restrict elf = get_elf_header(self);
	const Elf64_Phdr *const restrict begin = get_program_headers(self);
	const Elf64_Phdr *const restrict end = begin + elf->e_phnum;

	for (const Elf64_Phdr *restrict it = begin; it != end; it++) {
		if (is_loadable(it)) {
			uintptr_t vaddr = to_virtual_address(self, it->p_paddr);
			userland_copyin(self->pid, self->buf + it->p_offset, vaddr, it->p_filesz);
		}
	}
}

static void correct_rsp(reg_t *restrict regs) {
	const uintptr_t mask = ~(STACK_ALIGN - 1);
	regs->r_rsp = (register_t) ((regs->r_rsp & mask) - sizeof(mask));
}

static bool elf_start(elf_loader_t *restrict self, uintptr_t args) {
    //printf("imagebase: 0x%08llx\n", self->imagebase);
	reg_t regs;
	if (tracer_get_registers(&self->tracer, &regs)) {
		puts("elf_start failed to read process registers");
		return false;
	}
	if (regs.r_fs == 0) {
		puts("elf_start process is not ready (FS is 0)");
		return false;
	}
	correct_rsp(&regs);
	regs.r_rdi = (register_t) args;
	regs.r_rip = (register_t) to_virtual_address(self, get_elf_header(self)->e_entry);
	if (tracer_set_registers(&self->tracer, &regs)) {
		puts("elf_start failed to set registers");
		return false;
	}
	// it will run on detatch
	//puts("great success");
	return true;
}


static bool load_lib_sysmodule(elf_loader_t *restrict self) {
	const uintptr_t proc = get_proc(self->pid);

	int64_t handle = GET_LIB(self->pid, "libSceSysmodule.sprx");
	if (handle == -1) {
		puts("failed to get libSceSysmodule");
		return false;
	}

	//printf("handle: 0x%llx\n", handle);

	uintptr_t lib = proc_get_lib(proc, (int) handle);
	if (lib == 0) {
		puts("failed to get libSceSysmodule");
		return false;
	}

	uintptr_t meta = shared_lib_get_metadata(lib);
	uintptr_t imagebase = shared_lib_get_imagebase(lib);
	int res = resolver_add_library_metadata(&self->resolver, imagebase, meta);
	if (res) {
		printf("resolver_add_library_metadata(&self->resolver, imagebase, meta) -> %d\n", res);
		return false;
	}

	return true;
}

bool run_elf(uint8_t *buf, int pid) {
	elf_loader_t elf;
	if (elf_init(&elf, buf, pid)) {
		puts("run_elf elf_init failed");
		return false;
	}

	bool result = elf_loader_run(&elf);

	if (elf_finalize(&elf)) {
		puts("run_elf elf_finalize failed");
	}

	return result;
}

bool elf_loader_run(elf_loader_t *self) {

	//puts("processing dynamic table");
	process_dynamic_table(self);

	//puts("mapping elf memory");
	if (!map_elf_memory(self)) {
		puts("map_elf_memory failed");
		return false;
	}

	//puts("loading libSysmodule");
	if (!load_lib_sysmodule(self)) {
		puts("load_lib_sysmodule failed");
		return false;
	}

	//puts("loading libraries");
	if (!load_libraries(self)) {
		puts("load_libraries failed");
		return false;
	}

	//puts("processing relocations");
	if (!elf_process_relocations(self)) {
		puts("elf_process_relocations failed");
		return false;
	}

	//puts("setting up kernel rw");
	uintptr_t args = setup_kernel_rw(self);
	if (args == 0) {
		puts("setup_kernel_rw failed");
		return false;
	}

	//puts("loading elf into memory");
	elf_load(self);

	//puts("starting");
	return elf_start(self, args);
}

elf_loader_t *elf_loader_create(uint8_t *buf, int pid) {
	elf_loader_t *self = malloc(sizeof(elf_loader_t));
	if (elf_init(self, buf, pid)) {
		puts("elf_loader_create elf_init failed");
		return NULL;
	}
	return self;
}

void elf_loader_finalize(elf_loader_t *self) {
	if (elf_finalize(self)) {
		puts("run_elf elf_finalize failed");
	}
}

void elf_loader_delete(elf_loader_t *self) {
	if (self == NULL) {
		return;
	}
	elf_loader_finalize(self);
	free(self);
}