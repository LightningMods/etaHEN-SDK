#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/sysctl.h>

#define VERSION_MASK 0xffff0000

#define V300 0x3000000
#define V310 0x3100000
#define V320 0x3200000
#define V321 0x3210000
#define V400 0x4000000
#define V402 0x4020000
#define V403 0x4030000
#define V450 0x4500000
#define V451 0x4510000

static uint32_t get_system_software_version(void) {
	static uint32_t version;
	if (version != 0) {
		return version;
	}
	size_t size = 4;
	sysctlbyname("kern.sdk_version", &version, &size, NULL, 0);
	version &= VERSION_MASK;
	return version;
}

// NOLINTBEGIN(readability-magic-numbers)

size_t get_allproc_offset(void) {
	static size_t allprocOffset;
	if (allprocOffset != 0) {
		return allprocOffset;
	}
	switch(get_system_software_version()) {
		case V300:
		case V310:
		case V320:
		case V321:
			allprocOffset = 0x276DC58;
			break;
		case V400:
		case V402:
		case V403:
		case V450:
		case V451:
			allprocOffset = 0x27EDCB8;
			break;
		default:
		    printf("Unsupported firmware version: 0x%x\n", get_system_software_version() & VERSION_MASK);
			allprocOffset = -1;
			break;
	}
	return allprocOffset;
}

size_t get_security_flags_offset(void) {
	switch(get_system_software_version()) {
		case V300:
		case V310:
		case V320:
		case V321:
			return 0x6466474;
		case V400:
			return 0x6506474;
		case V402:
		case V403:
		case V450:
		case V451:
			return 0x6505474;
		default:
		    printf("Unsupported firmware version: 0x%x\n", get_system_software_version() & VERSION_MASK);
			return -1;
	}
}

size_t get_qa_flags_offset(void) {
	switch(get_system_software_version()) {
		case V300:
		case V310:
		case V320:
		case V321:
			return 0x6466498;
		case V400:
		case V402:
		case V403:
		case V450:
		case V451:
			return 0x6506498;
		default:
		    printf("Unsupported firmware version: 0x%x\n", get_system_software_version() & VERSION_MASK);
			return -1;
	}
}

size_t get_utoken_flags_offset(void) {
	switch(get_system_software_version()) {
		case V300:
		case V310:
		case V320:
		case V321:
			return 0x6466500;
		case V400:
		case V402:
		case V403:
		case V450:
		case V451:
			return 0x6506500;
		default:
		    printf("Unsupported firmware version: 0x%x\n", get_system_software_version() & VERSION_MASK);
			return -1;
	}
}

size_t get_root_vnode_offset(void) {
	switch(get_system_software_version()) {
		case V300:
		case V310:
		case V320:
		case V321:
			return 0x67AB4C0;
		case V400:
		case V402:
		case V403:
		case V450:
		case V451:
			return 0x66E74C0;
		default:
		    printf("Unsupported firmware version: 0x%x\n", get_system_software_version() & VERSION_MASK);
			return -1;
	}
}

// NOLINTEND(readability-magic-numbers)
