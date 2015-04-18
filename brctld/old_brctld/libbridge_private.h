#ifndef _LIBBRIDGE_PRIVATE_H
#define _LIBBRIDGE_PRIVATE_H


extern int br_socket_fd;
extern struct sysfs_class *br_class_net;
struct sysfs_class { const char *name; };

static inline struct sysfs_class *sysfs_open_class(const char *name)
{
	return NULL;
}

#endif