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
#include <klog.hpp>
#include <fcntl.h>
int main()
{
	if (!redirct_stdout())
	{
		return EXIT_FAILURE;
	}

	puts("Hello klog");
	printf("Hello klog %d\n", 1337);
	printf("============== END OF SAMPLE ============");

	return 0;
}