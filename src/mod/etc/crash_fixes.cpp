#include "mod.h"
#include "stub/baseentity.h"
#include "stub/tfweaponbase.h"
#include "stub/projectiles.h"
#include "stub/objects.h"
#include "stub/tfentities.h"
#include "stub/nextbot_cc.h"
#include "stub/gamerules.h"
#include "stub/nav.h"
#include "stub/misc.h"
#include "link/link.h"
#include "util/backtrace.h"
#include "util/clientmsg.h"
#include "util/misc.h"
#include "util/iterate.h"
#include "tier1/CommandBuffer.h"

namespace Mod::Etc::Crash_Fixes
{
	
	DETOUR_DECL_MEMBER(CBaseEntity *, CTFPipebombLauncher_FireProjectile, CTFPlayer *player)
	{
		auto proj = DETOUR_MEMBER_CALL(player);
		auto weapon = reinterpret_cast<CTFPipebombLauncher *>(this);
		if (rtti_cast<CTFGrenadePipebombProjectile *>(proj) == nullptr) {
			weapon->m_Pipebombs->RemoveAll();
			weapon->m_iPipebombCount = 0;
		}
		return proj;
	}

	DETOUR_DECL_MEMBER(void, CFuncIllusionary_Spawn)
	{
		auto entity = reinterpret_cast<CBaseEntity *>(this);
		CBaseEntity::PrecacheModel(STRING(entity->GetModelName()));
		DETOUR_MEMBER_CALL();
	}	
    StaticFuncThunk<CBaseEntity*> ft_GetCurrentSkyCamera("GetCurrentSkyCamera");

	DETOUR_DECL_STATIC(void, ClientData_Update, CBasePlayer *pl)
	{
        if (ft_GetCurrentSkyCamera() == nullptr) {
            pl->m_Local->m_skybox3darea = 255;
            return;
        }
		DETOUR_STATIC_CALL(pl);
	}	

#if defined _WINDOWS
	/* CVariantBase as the game passes it: 16 bytes by value, popped by the
	 * callee with the name (ret 0x14). Only passed through. */
	struct ScriptVariantBytes { uint32 data[4]; };

	/* A map's VScript can call Convars.SetValue from an entity's destroy
	 * callback while the level shuts down, after ~CWorld has deleted the game
	 * rules; SetValue then calls SaveConvar through a null g_pGameRules
	 * (mvm_skeleclipse_b7a_adv_vicious_delicious, on its way to another map).
	 * Linux has the same call; nothing there has been seen to reach it. */
	DETOUR_DECL_MEMBER(void, CScriptConvarAccessor_SetValue, const char *name, ScriptVariantBytes value)
	{
		if (g_pGameRules.GetRef() == nullptr) return;
		DETOUR_MEMBER_CALL(name, value);
	}
#endif

    class CMod : public IMod
	{
	public:
		CMod() : IMod("Etc:Crash_Fixes")
		{
			// Fix cfuncillusionary crash
			MOD_ADD_DETOUR_MEMBER(CFuncIllusionary_Spawn, "CFuncIllusionary::Spawn");

			// Fix arrow crash when firing too fast
			MOD_ADD_DETOUR_MEMBER(CTFPipebombLauncher_FireProjectile, "CTFPipebombLauncher::FireProjectile");

			// Fix crash after sky_camera being removed
			MOD_ADD_DETOUR_STATIC(ClientData_Update, "ClientData_Update");

#if defined _WINDOWS
			// Fix VScript's Convars.SetValue at level shutdown, once the game rules are gone
			MOD_ADD_DETOUR_MEMBER(CScriptConvarAccessor_SetValue, "CScriptConvarAccessor::SetValue");
#endif
		}
	};
	CMod s_Mod;

    ConVar cvar_enable("sig_etc_fix_misc_crash", "0", FCVAR_NOTIFY,
		"Mod:\nFixes crashes:"
		"\nWhen firing too many arrows"
		"\nWhen trying to detonate non grenades on pipebomb launcher"
		"\nAfter removing sky_camera",
		[](IConVar *pConVar, const char *pOldValue, float flOldValue){
			s_Mod.Toggle(static_cast<ConVar *>(pConVar)->GetBool());
		});
}