#include "mod.h"


namespace Mod::Attr::Undocumented
{
	ConVar cvar_parachute_disable("sig_attr_undocumented_parachute_disable", "0", FCVAR_NOTIFY,
		"");
	ConVar cvar_fires_milk_bolts("sig_attr_undocumented_fires_milk_bolts", "0", FCVAR_NOTIFY,
		"");
	ConVar cvar_force_distribute_currency_on_death("sig_attr_undocumented_force_distribute_currency_on_death", "0", FCVAR_NOTIFY,
		"");
	
	
#if defined _WINDOWS
	/* The game's function is a __thiscall member and pops its four arguments;
	 * declared static the detour would pop none of them. */
	DETOUR_DECL_MEMBER(float, CAttributeManager_ApplyAttributeFloatWrapper, float val, CBaseEntity *ent, string_t name, CUtlVector<CBaseEntity *> *vec)
#else
	DETOUR_DECL_STATIC(float, CAttributeManager_ApplyAttributeFloatWrapper, float val, CBaseEntity *ent, string_t name, CUtlVector<CBaseEntity *> *vec)
#endif
	{
		const char *attr = STRING(name);
		
		if (strcmp(attr, "parachute_disable") == 0) {
			return cvar_parachute_disable.GetFloat();
		}
		if (strcmp(attr, "fires_milk_bolts") == 0) {
			return cvar_fires_milk_bolts.GetFloat();
		}
		if (strcmp(attr, "force_distribute_currency_on_death") == 0) {
			return cvar_force_distribute_currency_on_death.GetFloat();
		}
		
#if defined _WINDOWS
		return DETOUR_MEMBER_CALL(val, ent, name, vec);
#else
		return DETOUR_STATIC_CALL(val, ent, name, vec);
#endif
	}
	
	
	class CMod : public IMod
	{
	public:
		CMod() : IMod("Attr:Undocumented")
		{
#if defined _WINDOWS
			MOD_ADD_DETOUR_MEMBER(CAttributeManager_ApplyAttributeFloatWrapper, "CAttributeManager::ApplyAttributeFloatWrapper");
#else
			MOD_ADD_DETOUR_STATIC(CAttributeManager_ApplyAttributeFloatWrapper, "CAttributeManager::ApplyAttributeFloatWrapper");
#endif
		}
	};
	CMod s_Mod;
	
	
	ConVar cvar_enable("sig_attr_undocumented", "0", FCVAR_NOTIFY,
		"Mod: enable undocumented attribute classes",
		[](IConVar *pConVar, const char *pOldValue, float flOldValue){
			s_Mod.Toggle(static_cast<ConVar *>(pConVar)->GetBool());
		});
}
