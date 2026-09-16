#pragma once
/* The SDK's platform.h, with RESTRICT disarmed.
 *
 * bitbuf.h declares bf_write::WriteUBitLong without RESTRICT and defines it
 * with one. Microsoft's compiler lets that pass; clang reads __restrict on a
 * member function as part of its type and calls the two a conflict, which is
 * 31 files' worth of the same error.
 *
 * RESTRICT is an optimiser hint about `this` and nothing else, so dropping it
 * costs some speed in the SDK's inline maths and changes no behaviour. The
 * alternative is editing the SDK, which the next checkout would undo.
 *
 * Only the unprefixed spelling is shimmed. common.h includes <platform.h> on
 * its line 347 and common.h is force-included into every source, so this runs
 * first; the real header has an include guard, so the <tier0/platform.h>
 * spelling other SDK headers use is a no-op by the time they reach it.
 */
#include_next <platform.h>

#undef RESTRICT
#define RESTRICT
