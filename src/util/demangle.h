#ifndef _INCLUDE_SIGSEGV_UTIL_DEMANGLE_H
#define _INCLUDE_SIGSEGV_UTIL_DEMANGLE_H

/* _MSC_VER is asked about before __clang__ here, and not the other way round,
 * because clang-cl defines both. Asked the other way, a Windows build takes the
 * libiberty branch, and there is no libiberty on Windows: the Itanium demangler
 * is for Linux symbols, which a Windows build does not have. src/abi.h had the
 * same order and the same fix. */


inline bool DemangleName(const char *mangled, std::string& result)
{
#if defined _MSC_VER
	result = mangled;
	return true;
#elif defined __clang__ || defined __GNUC__
	constexpr int options = DMGL_GNU_V3 | DMGL_TYPES | DMGL_ANSI | DMGL_PARAMS;
	char *demangled = cplus_demangle(mangled, options);
	
	if (demangled != nullptr) {
		result = demangled;
		free(demangled);
		return true;
	} else {
		result = mangled;
		return false;
	}
#endif
}


inline bool DemangleTypeName(const char *mangled, std::string& result)
{
#if defined _MSC_VER
	result = mangled;
	return true;
#elif defined __clang__ || defined __GNUC__
	char *prefixed = new char[strlen(mangled) + 1 + 4];
	strcpy(prefixed, "_ZTS");
	strcat(prefixed, mangled);
	
	constexpr int options = DMGL_GNU_V3 | DMGL_TYPES | DMGL_ANSI | DMGL_PARAMS;
	char *demangled = cplus_demangle(prefixed, options);
	
	delete[] prefixed;
	
	if (demangled != nullptr) {
		result = demangled;
		free(demangled);
		
		constexpr char strip[] = "typeinfo name for ";
		if (strncmp(result.c_str(), strip, strlen(strip)) == 0) {
			result = result.substr(strlen(strip));
		}
		
		return true;
	} else {
		result = mangled;
		return false;
	}
#endif
}

inline const char *DemangleTypeName(const std::type_info& typeinfo)
{
	const char *mangled = typeinfo.name();
	
#if defined _MSC_VER
	return mangled;
#elif defined __clang__ || defined __GNUC__
	std::string demangled;
	if (DemangleTypeName(mangled, demangled)) {
		extern string_t AllocPooledString(const char *pszValue);
		return STRING(AllocPooledString(demangled.c_str()));
	} else {
		return mangled;
	}
#endif
}


#endif