#pragma once
/* The POSIX calls this tree reaches through unistd.h, from where the Windows
 * CRT keeps them under the same names: access, unlink and close in io.h,
 * getpid in process.h, rmdir and getcwd in direct.h. */

#include <io.h>
#include <process.h>
#include <direct.h>
#include <BaseTsd.h>

typedef SSIZE_T ssize_t;

#ifndef F_OK
#define F_OK 0
#endif
