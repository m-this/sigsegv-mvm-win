#ifndef _INCLUDE_SIGSEGV_UTIL_UCS2_H_
#define _INCLUDE_SIGSEGV_UTIL_UCS2_H_


/* A game resource file (resource/tf_english.txt and the rest) is UTF-16 with
 * a byte order mark and no terminator. V_UCS2ToUTF8 converts up to a UCS-2
 * terminator, which on Windows is WideCharToMultiByte with a length of -1, so
 * converting the file buffer as it was read ran off its end: a read out of
 * bounds for every language, at load, and a server that died at map start.
 * The text is copied here with a terminator of its own. Empty when the file is
 * missing or holds nothing past the mark. */
inline std::string ReadUCS2ResourceAsUTF8(const char *path, const char *pathID)
{
	CUtlBuffer file(0, 0, CUtlBuffer::TEXT_BUFFER);
	if (!filesystem->ReadFile(path, pathID, file) || file.TellPut() <= 2) {
		return {};
	}

	size_t units = (file.TellPut() - 2) / sizeof(ucs2);
	std::vector<ucs2> text(units + 1, 0);
	memcpy(text.data(), static_cast<const char *>(file.Base()) + 2, units * sizeof(ucs2));

	/* A UTF-16 unit is at most three bytes of UTF-8, and a surrogate pair is
	 * four for two units. */
	std::string utf8(units * 3 + 1, '\0');
	_V_UCS2ToUTF8(text.data(), utf8.data(), utf8.size());
	utf8.resize(strnlen(utf8.c_str(), utf8.size()));
	return utf8;
}


#endif
