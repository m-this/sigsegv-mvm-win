#pragma once
/* Force-included when building for Windows.
 *
 * This code has only ever been compiled with libstdc++, whose headers include
 * most of the standard library in each other. MSVC's do not, so hundreds of
 * files that never named <cstdint> or <map> stop compiling on the first
 * uintptr_t or std::map they use.
 *
 * Adding the right include to each of those files is the correct fix and it is
 * several hundred edits against a tree that moves. This buys the same thing in
 * one flag while the port is being brought up, and lets the real number of
 * Windows-specific problems be counted without that noise on top.
 */
#include <cassert>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cctype>
#include <climits>
#include <ctime>
#include <cwchar>

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
#include <chrono>
#include <deque>
#include <forward_list>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <list>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stack>
#include <thread>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

/* ARRAY_SIZE is used by the tree and defined nowhere in it or in the SDK: on
 * Linux libiberty.h supplies it, reached through the demangler includes in
 * common.h, which a Windows build does not have. Same definition libiberty
 * gives. */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
