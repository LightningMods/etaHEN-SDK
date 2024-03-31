#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <notify.hpp>
#include <unistd.h>
#include <fcntl.h>
int main()
{
	int fd = open("/dev/console", O_WRONLY);
	if (fd == -1)
	{
		notify("Failed to open /dev/console");
		return 1;
	}

	dup2(fd, STDOUT_FILENO);
	dup2(STDOUT_FILENO, STDERR_FILENO);

	puts("Hello klog");
	printf("Hello klog %d\n", 1337);
	printf("============== END OF SAMPLE ============");

	return 0;
}