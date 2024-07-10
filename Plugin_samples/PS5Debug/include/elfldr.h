// Modified version of https://github.com/john-tornblom/ps5-payload-sdk/tree/master/samples/ptrace_elfldr
// Credits to John Tornblom

#pragma once

#include <stdint.h>

uintptr_t inject_elf(int pid, uint8_t* elf, size_t elfSize);