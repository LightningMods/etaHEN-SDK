#include "proc.h"
#include "ucred.h"
#include <stdint.h>


uintptr_t get_current_ucred(void) {
	static uintptr_t g_current_ucred = 0;
	if (g_current_ucred != 0) {
		return g_current_ucred;
	}
	g_current_ucred = proc_get_ucred(get_current_proc());
	return g_current_ucred;
}
