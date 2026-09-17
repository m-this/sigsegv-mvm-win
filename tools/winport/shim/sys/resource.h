#pragma once
/* getrusage, for the two profilers that read the process's CPU time out of it.
 * Only ru_utime and ru_stime are filled: they are the only fields this tree
 * reads, and GetProcessTimes is where Windows keeps them. */

#include <Windows.h>
#include <Winsock2.h>

#define RUSAGE_SELF 0

struct rusage
{
	struct timeval ru_utime;
	struct timeval ru_stime;
};

inline void rusage_filetime_to_timeval(const FILETIME &ft, struct timeval &tv)
{
	/* FILETIME counts 100 ns intervals */
	ULONGLONG us = ((ULONGLONG(ft.dwHighDateTime) << 32) | ft.dwLowDateTime) / 10;
	tv.tv_sec  = long(us / 1000000);
	tv.tv_usec = long(us % 1000000);
}

inline int getrusage(int who, struct rusage *usage)
{
	FILETIME creation, exit, kernel, user;
	if (who != RUSAGE_SELF || !GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
		return -1;
	}
	rusage_filetime_to_timeval(user, usage->ru_utime);
	rusage_filetime_to_timeval(kernel, usage->ru_stime);
	return 0;
}
