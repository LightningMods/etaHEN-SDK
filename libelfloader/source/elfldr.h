#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <elf.h>
#include "nid_resolver/resolver.h"
#include "tracer.h"

typedef struct elf_loader {
	tracer_t tracer;
	resolver_t resolver;
	uint8_t *buf;
	ssize_t text_index;
	ssize_t dynamic_index;
	Elf64_Rela *restrict reltab;
	size_t reltab_size;
	Elf64_Rela *restrict plttab;
	size_t plttab_size;
	Elf64_Sym *restrict symtab;
    size_t symtab_size;
	const char *strtab;
	uintptr_t imagebase;
	uintptr_t proc;
	int pid;
} elf_loader_t;

typedef struct elf_loader elf_loader_t;

// may return NULL
elf_loader_t *elf_loader_create(uint8_t *buf, int pid);
void elf_loader_finalize(elf_loader_t *self);
void elf_loader_delete(elf_loader_t *self);
bool elf_loader_run(elf_loader_t *self);
bool run_elf(uint8_t *buf, int pid);
void process_dynamic_table(elf_loader_t *restrict self);
