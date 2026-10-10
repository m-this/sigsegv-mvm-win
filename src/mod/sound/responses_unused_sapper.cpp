#include "mod.h"
#include "util/scope.h"


class CTFPlayer;


namespace Mod::Sound::Unused_Sapper
{
	RefCount rc_CObjectSapper_ApplyRoboSapperEffects;
	DETOUR_DECL_MEMBER_CALL_CONVENTION(__gcc_regcall, bool, CObjectSapper_ApplyRoboSapperEffects, CTFPlayer *target, float duration)
	{
		SCOPED_INCREMENT(rc_CObjectSapper_ApplyRoboSapperEffects);
		return DETOUR_MEMBER_CALL(target, duration);
	}

#if defined _WINDOWS
	/* ApplyRoboSapperEffects is inline there, and the rest of ApplyRoboSapper
	 * stuns no one */
	DETOUR_DECL_MEMBER(void, CObjectSapper_ApplyRoboSapper, CTFPlayer *target, float duration, int radius)
	{
		SCOPED_INCREMENT(rc_CObjectSapper_ApplyRoboSapperEffects);
		DETOUR_MEMBER_CALL(target, duration, radius);
	}
#endif
	
	DETOUR_DECL_MEMBER(bool, CTFPlayer_SpeakConceptIfAllowed, int iConcept, const char *modifiers, char *pszOutResponseChosen, size_t bufsize, IRecipientFilter *filter)
	{
		if (iConcept == MP_CONCEPT_STUNNED_TARGET && rc_CObjectSapper_ApplyRoboSapperEffects > 0) {
			iConcept = MP_CONCEPT_MVM_SAPPED_ROBOT;
		}
		
		return DETOUR_MEMBER_CALL(iConcept, modifiers, pszOutResponseChosen, bufsize, filter);
	}
	
	
	class CMod : public IMod
	{
	public:
		CMod() : IMod("Sound:Unused_Sapper")
		{
#if defined _WINDOWS
			MOD_ADD_DETOUR_MEMBER(CObjectSapper_ApplyRoboSapper,        "CObjectSapper::ApplyRoboSapper");
#else
			MOD_ADD_DETOUR_MEMBER(CObjectSapper_ApplyRoboSapperEffects, "CObjectSapper::ApplyRoboSapperEffects [clone]");
#endif
			MOD_ADD_DETOUR_MEMBER(CTFPlayer_SpeakConceptIfAllowed,      "CTFPlayer::SpeakConceptIfAllowed");
		}
	};
	CMod s_Mod;
	
	
	ConVar cvar_enable("sig_sound_unused_sapper", "0", FCVAR_NOTIFY,
		"Mod: enable unused TLK_MVM_SAPPED_ROBOT voice response when sapping a robot (instead of TLK_STUNNED_TARGET)",
		[](IConVar *pConVar, const char *pOldValue, float flOldValue){
			s_Mod.Toggle(static_cast<ConVar *>(pConVar)->GetBool());
		});
}
