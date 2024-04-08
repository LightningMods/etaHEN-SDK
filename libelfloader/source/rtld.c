#include "memory.h"
#include "offsets.h"
#include "proc.h"
#include "rtld.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/elf64.h>

void *malloc(size_t size);
void free(void *ptr);
#define SECTION_TYPE_TEXT 1
#define SECTION_TYPE_XOTEXT 2
#define SECTION_TYPE_DATA 16
#define SECTIONS_ITERATOR_OFFSET 0x40
#define TYPE_OFFSET 8
#define ADDRESS_OFFSET 8
#define LENGTH_OFFSET 16
#define ALLOCATION_ALIGNMENT 0x10
#define ALLOCATION_ALIGNMENT_MASK 0xf
#define LIB_HANDLE_OFFSET 0x28
#define LIB_PATH_OFFSET 0x8
#define METADATA_PLT_HELPER_OFFSET 0x28
#define NID_LENGTH 11

typedef struct {
	uintptr_t symtab;
	size_t symtab_size;
	uintptr_t strtab;
	size_t strtab_size;
	uintptr_t plttab;
	size_t plttab_size;
} plt_helper_t;

typedef struct {
	uintptr_t sections;
	size_t num_sections;
} sections_iterator_t;

typedef struct {
	uintptr_t type;
	uintptr_t start;
	size_t length;
} section_t;


uintptr_t get_proc(int target_pid) {
	uintptr_t proc = 0;
	kernel_copyout(kernel_base + get_allproc_offset(), &proc, sizeof(proc));
	while (proc != 0) {
		int pid = proc_get_pid(proc);
		if (pid == target_pid) {
			return proc;
		}
		proc = proc_get_next(proc);
	}
	return 0;
}

static int32_t section_get_type(const section_t *restrict section) {
	int32_t value = -1;
	kernel_copyout(section->type + TYPE_OFFSET, &value, sizeof(value));
	return value;
}

static int get_allocator(process_allocator_t *restrict self, uintptr_t proc, intptr_t types) {
	uintptr_t eboot = proc_get_eboot(proc);
	if (eboot == 0) {
		return -1;
	}

	sections_iterator_t sections;
	kernel_copyout(eboot + SECTIONS_ITERATOR_OFFSET, &sections, sizeof(sections));

	section_t section;
	for (size_t i = 0; i < sections.num_sections; i++) {
		section.type = 0;
		kernel_copyout(sections.sections + (i * sizeof(section)), &section, sizeof(section));
		if (section.type == 0) {
			// copyout failed
			return -1;
		}
		intptr_t type = section_get_type(&section);
		if (type == -1) {
			// invalid type
			return -1;
		}
		if (type & types) {
			// type found
			self->page_end = section.start + section.length;
			self->consumed = 0;
			return 0;
		}
	}
	return 1;
}

int get_text_allocator(process_allocator_t *restrict self, uintptr_t proc) {
	int err = get_allocator(self, proc, SECTION_TYPE_TEXT | SECTION_TYPE_XOTEXT);
	if (err == 1) {
		puts("failed to find the .text section");
	} else if (err == -1) {
		puts("an error occured while locating the .text section");
	}
	return err;
}

int get_data_allocator(process_allocator_t *restrict self, uintptr_t proc) {
	int err = get_allocator(self, proc, SECTION_TYPE_DATA);
	if (err == 1) {
		puts("failed to find the .data section");
	} else if (err == -1) {
		puts("an error occured while locating the .data section");
	}
	return err;
}

uintptr_t process_allocator_allocate(process_allocator_t *restrict self, size_t length) {
	if ((length & ALLOCATION_ALIGNMENT_MASK) != 0) {
		length = (length & ~ALLOCATION_ALIGNMENT_MASK) + ALLOCATION_ALIGNMENT;
	}
	self->consumed += length;
	return self->page_end - self->consumed;
}

static uintptr_t shared_object_get_lib(uintptr_t obj, int handle) {
	uintptr_t lib = 0;
	kernel_copyout(obj, &lib, sizeof(lib));
	while (lib != 0) {
		int current_handle = -1;
		kernel_copyout(lib + LIB_HANDLE_OFFSET, &current_handle, sizeof(current_handle));
		if (current_handle == -1) {
			// read failed
			return -1;
		}
		if (current_handle == handle) {
			return lib;
		}
		kernel_copyout(lib, &lib, sizeof(lib));
	}
	return 0;
}

uintptr_t proc_get_lib(uintptr_t proc, int handle) {
	uintptr_t obj = proc_get_shared_object(proc);
	return shared_object_get_lib(obj, handle);
}

static size_t get_symbol_address(const plt_helper_t *restrict helper, uintptr_t imagebase, const char *nid) {
	Elf64_Sym *symtab = malloc(helper->symtab_size);
	if (symtab == NULL) {
		return 0;
	}

	kernel_copyout(helper->symtab, symtab, helper->symtab_size);

	char *strtab = malloc(helper->strtab_size);
	if (strtab == NULL) {
		free(symtab);
		return 0;
	}

	kernel_copyout(helper->strtab, strtab, helper->strtab_size);

	const size_t num_symbols = helper->symtab_size / sizeof(Elf64_Sym);
	size_t addr = 0;
	for (size_t i = 1; i < num_symbols; i++) {
		if (memcmp(nid, strtab + symtab[i].st_name, NID_LENGTH) == 0) {
			addr = imagebase + symtab[i].st_value;
			break;
		}
	}

	free(symtab);
	free(strtab);
	return addr;
}

uintptr_t shared_lib_get_address(uintptr_t lib, const char *sym_nid) {
	plt_helper_t helper;
	uintptr_t meta = shared_lib_get_metadata(lib);
	if (meta == 0) {
		return 0;
	}
	uintptr_t imagebase = shared_lib_get_imagebase(lib);
	if (imagebase == 0) {
		return 0;
	}
	kernel_copyout(meta  + METADATA_PLT_HELPER_OFFSET, &helper, sizeof(plt_helper_t));
	return get_symbol_address(&helper, imagebase, sym_nid);
}

static size_t get_symbol_index(const plt_helper_t *restrict helper, const char *nid) {
	Elf64_Sym *symtab = malloc(helper->symtab_size);
	if (symtab == NULL) {
		return 0;
	}

	kernel_copyout(helper->symtab, symtab, helper->symtab_size);

	char *strtab = malloc(helper->strtab_size);
	if (strtab == NULL) {
		free(symtab);
		return 0;
	}

	kernel_copyout(helper->strtab, strtab, helper->strtab_size);

	const size_t num_symbols = helper->symtab_size / sizeof(Elf64_Sym);
	size_t index = 0;
	for (size_t i = 1; i < num_symbols; i++) {
		if (memcmp(nid, strtab + symtab[i].st_name, NID_LENGTH) == 0) {
			index = i;
			break;
		}
	}

	free(symtab);
	free(strtab);
	return index;
}

size_t metadata_get_plt_offset(uintptr_t meta, const char *sym_nid) {
	plt_helper_t helper;
	kernel_copyout(meta  + METADATA_PLT_HELPER_OFFSET, &helper, sizeof(plt_helper_t));

	const size_t symbol_index = get_symbol_index(&helper, sym_nid);
	if (symbol_index == 0) {
		return 0;
	}

	Elf64_Rela *reltbl = malloc(helper.plttab_size);
	if (reltbl == 0) {
		return 0;
	}

	kernel_copyout(helper.plttab, reltbl, helper.plttab_size);

	const size_t count = helper.plttab_size / sizeof(Elf64_Rela);
	size_t offset = 0;
	for (size_t i = 0; i < count; i++) {
		if (ELF64_R_SYM(reltbl[i].r_info) == symbol_index) {
			offset = reltbl[i].r_offset;
			break;
		}
	}

	free(reltbl);
	return offset;
}
