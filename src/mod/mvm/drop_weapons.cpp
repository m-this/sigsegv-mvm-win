#include "mod.h"
#include "stub/tfentities.h"
#include "stub/tfplayer.h"
#include "stub/gamerules.h"
#include "util/scope.h"


namespace Mod::MvM::Drop_Weapons
{
#if defined _WINDOWS
	/* ShouldDropAmmoPack is inline in Event_Killed there, and its MvM bot test is
	 * what keeps a robot from dropping anything: drop before the game's Event_Killed */
	DETOUR_DECL_MEMBER(void, CTFPlayer_Event_Killed, const CTakeDamageInfo& info)
	{
		auto player = reinterpret_cast<CTFPlayer *>(this);
		if (player->IsBot() && TFGameRules()->IsMannVsMachineMode()) {
			player->DropAmmoPack(info, false, false);
		}
		DETOUR_MEMBER_CALL(info);
	}
	
	/* TFBot_Extensions drops from its own Event_Killed detour: one drop per death */
	CTFPlayer *last_drop_player = nullptr;
	int last_drop_tick = -1;
#else
	DETOUR_DECL_MEMBER(bool, CTFPlayer_ShouldDropAmmoPack)
	{
		auto player = reinterpret_cast<CTFPlayer *>(this);
		
		if (player != nullptr && player->IsBot() && TFGameRules()->IsMannVsMachineMode()) {
			return true;
		}
		
		return DETOUR_MEMBER_CALL();
	}
#endif
	
	RefCount rc_CTFPlayer_DropAmmoPack;
	CTFPlayer *drop_player = nullptr;
	DETOUR_DECL_MEMBER(void, CTFPlayer_DropAmmoPack, const CTakeDamageInfo& info, bool b1, bool b2)
	{
#if defined _WINDOWS
		auto player = reinterpret_cast<CTFPlayer *>(this);
		if (player == last_drop_player && gpGlobals->tickcount == last_drop_tick) return;
		last_drop_player = player;
		last_drop_tick = gpGlobals->tickcount;
#endif
		SCOPED_INCREMENT(rc_CTFPlayer_DropAmmoPack);
		drop_player = reinterpret_cast<CTFPlayer *>(this);
		
		DETOUR_MEMBER_CALL(info, b1, b2);
		
		drop_player = nullptr;
	}
	
	DETOUR_DECL_STATIC(CTFAmmoPack *, CTFAmmoPack_Create, const Vector& vecOrigin, const QAngle& vecAngles, CBaseEntity *pOwner, const char *pszModelName)
	{
		if (rc_CTFPlayer_DropAmmoPack > 0 && drop_player != nullptr && drop_player->IsBot() && TFGameRules()->IsMannVsMachineMode()) {
			return nullptr;
		}
		
		return DETOUR_STATIC_CALL(vecOrigin, vecAngles, pOwner, pszModelName);
	}
	
	DETOUR_DECL_STATIC(CTFDroppedWeapon *, CTFDroppedWeapon_Create, const Vector& vecOrigin, const QAngle& vecAngles, CBaseEntity *pOwner, const char *pszModelName, const CEconItemView *pItemView)
	{
		if (!TFGameRules()->IsMannVsMachineMode()) {
			return DETOUR_STATIC_CALL(vecOrigin, vecAngles, pOwner, pszModelName, pItemView);
		}
		
		TFGameRules()->Set_m_bPlayingMannVsMachine(false);
		CTFDroppedWeapon *pDroppedWeapon = DETOUR_STATIC_CALL(vecOrigin, vecAngles, pOwner, pszModelName, pItemView);
		TFGameRules()->Set_m_bPlayingMannVsMachine(true);
		return pDroppedWeapon;
	}
	
	
	class CMod : public IMod
	{
	public:
		CMod() : IMod("MvM:Drop_Weapons")
		{
#if defined _WINDOWS
			MOD_ADD_DETOUR_MEMBER(CTFPlayer_Event_Killed,       "CTFPlayer::Event_Killed");
#else
			MOD_ADD_DETOUR_MEMBER(CTFPlayer_ShouldDropAmmoPack, "CTFPlayer::ShouldDropAmmoPack");
#endif
			MOD_ADD_DETOUR_MEMBER(CTFPlayer_DropAmmoPack,       "CTFPlayer::DropAmmoPack");
			MOD_ADD_DETOUR_STATIC(CTFAmmoPack_Create,           "CTFAmmoPack::Create");
			MOD_ADD_DETOUR_STATIC(CTFDroppedWeapon_Create,      "CTFDroppedWeapon::Create");
		}
	};
	CMod s_Mod;
	
	
	ConVar cvar_enable("sig_mvm_drop_weapons", "0", FCVAR_NOTIFY,
		"Mod: make MvM robots drop their weapon upon death (but not ammo packs)",
		[](IConVar *pConVar, const char *pOldValue, float flOldValue){
			s_Mod.Toggle(static_cast<ConVar *>(pConVar)->GetBool());
		});
}
