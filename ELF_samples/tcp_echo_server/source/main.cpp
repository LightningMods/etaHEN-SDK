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

#define PORT 50
#define BUFSIZE 1024

int main()
{
	int server_fd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char buffer[BUFSIZE] = {0};
	ssize_t n;

	// Creating socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		notify("socket failed with %s", strerror(errno));
		return -1;
	}

	// Forcefully attaching socket to the port 50
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
	{
		notify("setsockopt failed with %s", strerror(errno));
		return -1;
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);

	// Forcefully attaching socket to the port 50
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		notify("bind failed with %s", strerror(errno));
		return -1;
	}

	if (listen(server_fd, 3) < 0)
	{
		notify("listen failed with %s", strerror(errno));
		return -1;
	}

	notify("Echo server is listening on port %d", PORT);

	if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
	{
		perror("accept");
		return -1;
	}

	// Echo back the message that came in
	while ((n = read(new_socket, buffer, BUFSIZE)) > 0)
	{
		notify("response: %s", buffer);
		write(new_socket, buffer, n);
		(void)memset(buffer, 0, BUFSIZE); // Clear the buffer after each message
	}

	if (n < 0)
	{
		perror("read error");
		return -1;
	}

	notify("Closing server");

	close(new_socket);
	close(server_fd);

	return 0;
}