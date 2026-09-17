/* The one header every extension source is compiled with, and the header the
 * precompiled header is built from: the prelude, then the tree's own common.h,
 * which the Linux build force-includes too (AMBuilder:546). */
#include "msvc_prelude.h"
#include "../../src/common.h"
