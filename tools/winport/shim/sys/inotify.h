#pragma once
/* inotify does not exist on Windows. inotify_init1 reports that, and every use
 * in this tree is behind a check for a valid descriptor, so the download
 * manager's refresh-on-change stays off rather than failing. The rest is here
 * only so those guarded paths compile. */

#include <cerrno>
#include <cstdint>

#define IN_NONBLOCK 0x800
#define IN_MODIFY   0x002
#define IN_CREATE   0x100
#define IN_DELETE   0x200
#define IN_MOVED_TO 0x080

struct inotify_event
{
	int      wd;
	uint32_t mask;
	uint32_t cookie;
	uint32_t len;
	char     name[];
};

inline int inotify_init1(int flags) { errno = ENOSYS; return -1; }
inline int inotify_add_watch(int fd, const char *path, uint32_t mask) { errno = ENOSYS; return -1; }
inline int inotify_rm_watch(int fd, int wd) { errno = ENOSYS; return -1; }
