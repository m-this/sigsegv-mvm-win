//#include "cbase.h"
#include "debugoverlay_shared.h"
#include "mathlib/mathlib.h"

// sigsegv: needed for our listen-server-host hackery to work properly
#include "stub/baseplayer.h"

// memdbgon must be the last include file in a .cpp file!!!
#include "tier0/memdbgon.h"

#define	MAX_OVERLAY_DIST_SQR	90000000

#if defined _WINDOWS
/* MSVC makes an empty body a lone ret, which a detour cannot patch and the
 * linker may fold with others; Overlay_Send detours the empty ones below. */
static const char *volatile s_EmptyOverlayCall;
__declspec(noinline) static void EmptyOverlayCall(const char *name)
{
	s_EmptyOverlayCall = name;
}
#endif

CBasePlayer *GetLocalPlayer( void )
{
	// sigsegv: horrendously ugly hack!
	static ConVarRef player_index("sig_util_listenserverhost_index");
	return UTIL_PlayerByIndex(player_index.GetInt());
#if 0
#if defined( CLIENT_DLL)
	return C_BasePlayer::GetLocalPlayer();
#else
	return UTIL_GetListenServerHost();
#endif
#endif
}

// sigsegv: convenience function
void NDebugOverlay::Clear()
{
	if (debugoverlay != nullptr) {
		debugoverlay->ClearAllOverlays();
	}
}

// sigsegv: exactly the same as Line, but with an alpha argument, and we call AddLineOverlayAlpha instead
void NDebugOverlay::LineAlpha(const Vector& origin, const Vector& target, int r, int g, int b, int a, bool noDepthTest, float flDuration)
{
	// --------------------------------------------------------------
	// Clip the line before sending so we 
	// don't overflow the client message buffer
	// --------------------------------------------------------------
	CBasePlayer *player = GetLocalPlayer();
	
	if (player == nullptr) {
		return;
	}
	
	// Clip line that is far away
	if (((player->GetAbsOrigin() - origin).LengthSqr() > MAX_OVERLAY_DIST_SQR) &&
		((player->GetAbsOrigin() - target).LengthSqr() > MAX_OVERLAY_DIST_SQR)) {
		return;
	}
	
	// Clip line that is behind the client 
	Vector clientForward;
	player->EyeVectors( &clientForward );
	
	Vector toOrigin = origin - player->GetAbsOrigin();
	Vector toTarget = target - player->GetAbsOrigin();
	float dotOrigin = DotProduct(clientForward, toOrigin);
	float dotTarget = DotProduct(clientForward, toTarget);
	
	if (dotOrigin < 0.0f && dotTarget < 0.0f) {
		return;
	}

	if (debugoverlay != nullptr)
	{
		debugoverlay->AddLineOverlayAlpha(origin, target, r, g, b, a, noDepthTest, flDuration);
	}
}

// sigsegv: only implemented in overlay recv mod
void NDebugOverlay::ScreenRect(float xFrom, float yFrom, float xTo, float yTo, const Color& cFill, const Color& cEdge, float flDuration)
{
#if defined _WINDOWS
	EmptyOverlayCall("ScreenRect");
#endif
}

// sigsegv: only implemented in overlay recv mod
void NDebugOverlay::ScreenLine(float xFrom, float yFrom, float xTo, float yTo, const Color& cFrom, const Color& cTo, float flDuration)
{
#if defined _WINDOWS
	EmptyOverlayCall("ScreenLine 2 colors");
#endif
}

// sigsegv: only implemented in overlay recv mod
void NDebugOverlay::ScreenLine(float xFrom, float yFrom, float xTo, float yTo, const Color& color, float flDuration)
{
#if defined _WINDOWS
	EmptyOverlayCall("ScreenLine 1 color");
#endif
}