#include "mod.h"
#include "util/scope.h"
#include "stub/tfplayer.h"
#include "stub/tfentities.h"

namespace Mod::MvM::GoBackInTime
{
	RefCount rc_CTFSniperRifle_ExplosiveHeadShot;
	DETOUR_DECL_MEMBER(void, CTFSniperRifle_ExplosiveHeadShot, CTFPlayer *player1, CTFPlayer *player2)
	{
		SCOPED_INCREMENT(rc_CTFSniperRifle_ExplosiveHeadShot);

		DETOUR_MEMBER_CALL(player1, player2);
	}

	RefCount rc_CTFPlayerShared_OnRemovePhase;
	DETOUR_DECL_MEMBER(void, CTFPlayerShared_OnRemovePhase)
	{
		SCOPED_INCREMENT(rc_CTFPlayerShared_OnRemovePhase);

		DETOUR_MEMBER_CALL();
	}

#if defined _WINDOWS
	/* OnRemovePhase is inline in OnConditionRemoved there, which tail calls it
	 * for this one condition on Linux */
	DETOUR_DECL_MEMBER(void, CTFPlayerShared_OnConditionRemoved, ETFCond cond)
	{
		SCOPED_INCREMENT_IF(rc_CTFPlayerShared_OnRemovePhase, cond == TF_COND_PHASE);

		DETOUR_MEMBER_CALL(cond);
	}
#endif


	DETOUR_DECL_MEMBER(void, CTFPlayerShared_StunPlayer, float duration, float slowdown, int flags, CTFPlayer *attacker)
	{
		if (rc_CTFSniperRifle_ExplosiveHeadShot > 0 || rc_CTFPlayerShared_OnRemovePhase > 0){
			return;
		}
		
		DETOUR_MEMBER_CALL(duration, slowdown, flags, attacker);
	}
	
	DETOUR_DECL_MEMBER(void, CTFPlayerShared_MakeBleed, CTFPlayer *attacker, CTFWeaponBase *weapon, float bleedTime, int bleeddmg, bool perm, int val)
	{
		if (rc_CTFSniperRifle_ExplosiveHeadShot > 0) {
			auto player = reinterpret_cast<CTFPlayerShared *>(this)->GetOuter();

			DevMsg("Damage before: %d %f\n", bleeddmg, bleedTime);

			bleeddmg = bleeddmg / 6;
			bleedTime = 3.0f;

			DevMsg("Damage after: %d\n",bleeddmg);
		}
		DETOUR_MEMBER_CALL(attacker, weapon, bleedTime, bleeddmg, perm, val);
	}
	
	DETOUR_DECL_STATIC(CTFReviveMarker *, CTFReviveMarker_Create, CTFPlayer *player)
	{
		return nullptr;
	}

	class CMod : public IMod
	{
	public:
		CMod() : IMod("MvM:No_Halloween_Souls")
		{
		
			MOD_ADD_DETOUR_MEMBER(CTFSniperRifle_ExplosiveHeadShot, "CTFSniperRifle::ExplosiveHeadShot");
#if defined _WINDOWS
			MOD_ADD_DETOUR_MEMBER(CTFPlayerShared_OnConditionRemoved, "CTFPlayerShared::OnConditionRemoved");
#else
			MOD_ADD_DETOUR_MEMBER(CTFPlayerShared_OnRemovePhase,    "CTFPlayerShared::OnRemovePhase");
#endif
			MOD_ADD_DETOUR_MEMBER(CTFPlayerShared_StunPlayer,       "CTFPlayerShared::StunPlayer");
			MOD_ADD_DETOUR_MEMBER(CTFPlayerShared_MakeBleed,        "CTFPlayerShared::MakeBleed");
			MOD_ADD_DETOUR_STATIC(CTFReviveMarker_Create,           "CTFReviveMarker::Create");
		}
	};
	CMod s_Mod;
	
	
	ConVar cvar_enable("sig_mvm_go_back_in_time", "0", FCVAR_NOTIFY,
		"Mod: revert old mvm features",
		[](IConVar *pConVar, const char *pOldValue, float flOldValue){
			s_Mod.Toggle(static_cast<ConVar *>(pConVar)->GetBool());
		});
}
