#include <stddef.h>
#include <stdint.h>
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

static uint32_t version;
size_t allprocOffset;

static uint32_t get_system_software_version(void) {
	uint32_t version = 0;
	size_t size = sizeof(version);
	sysctlbyname("kern.sdk_version", &version, &size, NULL, 0);
	return version & VERSION_MASK;
}

// NOLINTBEGIN(readability-magic-numbers)
static size_t get_allproc_offset(void) {
	switch(version) {
		case V300:
		case V310:
		case V320:
		case V321:
			return 0x276DC58;
		case V400:
		case V402:
		case V403:
		case V450:
		case V451:
			return 0x27EDCB8;
		default:
			return -1;
	}
}
// NOLINTEND(readability-magic-numbers)

static void __attribute__((constructor)) init(void) {
	version = get_system_software_version();
	allprocOffset = get_allproc_offset();
}
