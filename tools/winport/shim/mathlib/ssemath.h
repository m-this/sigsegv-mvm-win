#pragma once
/* The SDK's ssemath.h, with its four SSE accessors taking the portable path.
 *
 * SubFloat and SubInt read a lane of an __m128 as a.m128_f32[i], which is a
 * union member Microsoft's compiler puts on the type and clang does not, even
 * in MSVC mode: __m128 is a builtin vector there and has no members at all.
 * The header's own POSIX branch does the same job with a reinterpret_cast,
 * which any compiler takes and which is what m128_f32 is underneath.
 *
 * POSIX appears four times in that file and all four are those accessors, so
 * defining it here changes nothing else. It is defined for the length of this
 * include and put back afterwards, because everywhere else in the SDK POSIX
 * means "not Windows" and this build is Windows.
 *
 * First on the include path, ahead of the SDK's own copy, which include_next
 * then reaches.
 */

#ifdef POSIX
#include_next <mathlib/ssemath.h>
#else
#define POSIX 1
#include_next <mathlib/ssemath.h>
#undef POSIX
#endif
