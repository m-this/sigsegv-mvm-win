#pragma once
/* opendir, readdir, rewinddir and closedir over FindFirstFile, for the
 * download manager's walks of the population and map directories. d_name and
 * d_type are the only fields this tree reads. */

#include <Windows.h>
#include <cstring>
#include <string>

#define DT_UNKNOWN 0
#define DT_DIR     4
#define DT_REG     8

struct dirent
{
	unsigned char d_type;
	char d_name[MAX_PATH];
};

struct DIR
{
	std::string pattern;
	HANDLE find;
	WIN32_FIND_DATAA data;
	bool have_data;
	struct dirent entry;
};

inline DIR *opendir(const char *path)
{
	DIR *dir = new DIR;
	dir->pattern = std::string(path) + "\\*";
	dir->find = FindFirstFileA(dir->pattern.c_str(), &dir->data);
	if (dir->find == INVALID_HANDLE_VALUE) {
		delete dir;
		return nullptr;
	}
	dir->have_data = true;
	return dir;
}

inline struct dirent *readdir(DIR *dir)
{
	if (!dir->have_data) {
		return nullptr;
	}
	strncpy(dir->entry.d_name, dir->data.cFileName, sizeof(dir->entry.d_name) - 1);
	dir->entry.d_name[sizeof(dir->entry.d_name) - 1] = '\0';
	dir->entry.d_type = (dir->data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? DT_DIR : DT_REG;
	dir->have_data = FindNextFileA(dir->find, &dir->data) != 0;
	return &dir->entry;
}

inline void rewinddir(DIR *dir)
{
	FindClose(dir->find);
	dir->find = FindFirstFileA(dir->pattern.c_str(), &dir->data);
	dir->have_data = dir->find != INVALID_HANDLE_VALUE;
}

inline int closedir(DIR *dir)
{
	if (dir->find != INVALID_HANDLE_VALUE) {
		FindClose(dir->find);
	}
	delete dir;
	return 0;
}
