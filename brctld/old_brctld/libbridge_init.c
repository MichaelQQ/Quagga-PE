#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

#include "libbridge.h"
#include "libbridge_private.h"

int br_socket_fd = -1;
struct sysfs_class *br_class_net;

int br_init(void)
{
	if ((br_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return errno;

	br_class_net = sysfs_open_class("net");
	return 0;
}