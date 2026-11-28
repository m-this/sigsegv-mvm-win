#include "mod.h"
#include "stub/team.h"
#include "stub/tfplayer.h"
#include "stub/tfbot.h"
#include "stub/populators.h"
#include "util/scope.h"

#if defined _LINUX
#include <execinfo.h>
#include <dlfcn.h>
#endif


namespace Mod::Debug::Team_Lists
{
	constexpr int team_count = 4;
	int reports_left = 200;

	void PrintStack()
	{
#if defined _LINUX
		void *frames[24];
		int count = backtrace(frames, 24);
		for (int i = 1; i < count; i++) {
			Dl_info info;
			if (dladdr(frames[i], &info) != 0 && info.dli_fname != nullptr) {
				const char *name = strrchr(info.dli_fname, '/');
				Msg("  #%d %s+%#x\n", i, name != nullptr ? name + 1 : info.dli_fname, (unsigned int)((uintptr_t)frames[i] - (uintptr_t)info.dli_fbase));
			} else {
				Msg("  #%d %p\n", i, frames[i]);
			}
		}
#endif
	}

	void Report(const char *what, CTeam *team, CBasePlayer *player)
	{
		if (reports_left <= 0) return;
		--reports_left;
		Msg("TEAMLISTS %s: team %d, player #%d \"%s\" m_iTeamNum %d, alive %d, list %d\n",
			what, team->GetTeamNumber(), ENTINDEX(player), player->GetPlayerName(), player->GetTeamNumber(), player->IsAlive(), team->m_aPlayers->Count());
		PrintStack();
	}

	bool mismatch_reported[MAX_PLAYERS + 1] {};

	void CheckAll(const char *where)
	{
		for (int i = 1; i <= gpGlobals->maxClients && i <= MAX_PLAYERS; i++) {
			CBasePlayer *player = UTIL_PlayerByIndex(i);
			if (player == nullptr) continue;
			int listed = -1;
			int lists = 0;
			for (int t = 0; t < team_count; t++) {
				CTeam *team = TFTeamMgr()->GetTeam(t);
				if (team != nullptr && team->m_aPlayers->Find(player) != -1) {
					listed = t;
					lists++;
				}
			}
			bool bad = lists > 1 || (lists == 1 && listed != player->GetTeamNumber());
			if (bad && !mismatch_reported[i] && reports_left > 0) {
				--reports_left;
				Msg("TEAMLISTS mismatch after %s: tick %d, player #%d \"%s\" m_iTeamNum %d, listed by team %d (%d lists), alive %d, bot %d\n",
					where, gpGlobals->tickcount, i, player->GetPlayerName(), player->GetTeamNumber(), listed, lists, player->IsAlive(), player->IsBot());
				PrintStack();
			}
			mismatch_reported[i] = bad;
		}
	}

	DETOUR_DECL_MEMBER(void, CTFTeam_AddPlayer, CBasePlayer *player)
	{
		auto team = reinterpret_cast<CTeam *>(this);
		if (team->m_aPlayers->Find(player) != -1) {
			Report("add of a listed player", team, player);
		}
		for (int i = 0; i < team_count; i++) {
			CTeam *other = TFTeamMgr()->GetTeam(i);
			if (other != nullptr && other != team && other->m_aPlayers->Find(player) != -1) {
				Report("add of a player another team lists", other, player);
			}
		}
		DETOUR_MEMBER_CALL(player);
	}

	DETOUR_DECL_MEMBER(void, CTFTeam_RemovePlayer, CBasePlayer *player)
	{
		auto team = reinterpret_cast<CTeam *>(this);
		if (team->GetTeamNumber() != TEAM_UNASSIGNED && team->m_aPlayers->Find(player) == -1) {
			Report("remove of an unlisted player", team, player);
		}
		DETOUR_MEMBER_CALL(player);
	}

	DETOUR_DECL_MEMBER(void, CTFPlayer_UpdateOnRemove)
	{
		auto player = reinterpret_cast<CTFPlayer *>(this);
		DETOUR_MEMBER_CALL();
		for (int i = 0; i < team_count; i++) {
			CTeam *team = TFTeamMgr()->GetTeam(i);
			if (team != nullptr && team->m_aPlayers->Find(player) != -1) {
				Report("removed player still listed", team, player);
			}
		}
	}

	DETOUR_DECL_MEMBER(void, CPopulationManager_WaveEnd, bool b1)
	{
		CheckAll("before CPopulationManager::WaveEnd");
		DETOUR_MEMBER_CALL(b1);
		CheckAll("CPopulationManager::WaveEnd");
	}

	DETOUR_DECL_MEMBER(void, CWave_WaveCompleteUpdate)
	{
		DETOUR_MEMBER_CALL();
		CheckAll("CWave::WaveCompleteUpdate");
	}

	DETOUR_DECL_MEMBER(void, CTFPlayer_Event_Killed, const CTakeDamageInfo& info)
	{
		DETOUR_MEMBER_CALL(info);
		CheckAll("CTFPlayer::Event_Killed");
	}

	DETOUR_DECL_MEMBER(void, CTFPlayer_ForceRespawn)
	{
		DETOUR_MEMBER_CALL();
		CheckAll("CTFPlayer::ForceRespawn");
	}

	DETOUR_DECL_MEMBER(void, CTFPlayer_StateEnter, int nState)
	{
		DETOUR_MEMBER_CALL(nState);
		CheckAll("CTFPlayer::StateEnter");
	}

	DETOUR_DECL_MEMBER(ActionResult<CTFBot>, CTFBotMainAction_Update, CTFBot *actor, float dt)
	{
		auto result = DETOUR_MEMBER_CALL(actor, dt);
		CheckAll("CTFBotMainAction::Update");
		return result;
	}

	RefCount rc_CBasePlayer_ChangeTeam;
	DETOUR_DECL_MEMBER(void, CBasePlayer_ChangeTeam, int iTeamNum, bool b1, bool b2, bool b3)
	{
		SCOPED_INCREMENT(rc_CBasePlayer_ChangeTeam);
		DETOUR_MEMBER_CALL(iTeamNum, b1, b2, b3);
	}

	DETOUR_DECL_MEMBER(void, CBaseEntity_ChangeTeam, int iTeamNum)
	{
		auto entity = reinterpret_cast<CBaseEntity *>(this);
		if (rc_CBasePlayer_ChangeTeam == 0 && entity->IsPlayer() && reports_left > 0) {
			--reports_left;
			Msg("TEAMLISTS CBaseEntity::ChangeTeam(%d) on player #%d \"%s\" m_iTeamNum %d\n",
				iTeamNum, ENTINDEX(entity), static_cast<CBasePlayer *>(entity)->GetPlayerName(), entity->GetTeamNumber());
			PrintStack();
		}
		DETOUR_MEMBER_CALL(iTeamNum);
	}

	class CMod : public IMod, public IFrameUpdatePreEntityThinkListener, public IFrameUpdatePostEntityThinkListener
	{
	public:
		virtual bool ShouldReceiveCallbacks() const override { return this->IsEnabled(); }
		virtual void FrameUpdatePreEntityThink() override { CheckAll("frame start"); }
		virtual void FrameUpdatePostEntityThink() override { CheckAll("entity think"); }

		CMod() : IMod("Debug:Team_Lists")
		{
			MOD_ADD_DETOUR_MEMBER(CPopulationManager_WaveEnd, "CPopulationManager::WaveEnd");
			MOD_ADD_DETOUR_MEMBER(CWave_WaveCompleteUpdate,   "CWave::WaveCompleteUpdate");
			MOD_ADD_DETOUR_MEMBER(CTFPlayer_Event_Killed,     "CTFPlayer::Event_Killed");
			MOD_ADD_DETOUR_MEMBER(CTFPlayer_ForceRespawn,     "CTFPlayer::ForceRespawn");
			MOD_ADD_DETOUR_MEMBER(CTFPlayer_StateEnter,       "CTFPlayer::StateEnter");
			MOD_ADD_DETOUR_MEMBER(CTFBotMainAction_Update,    "CTFBotMainAction::Update");
			MOD_ADD_DETOUR_MEMBER(CBasePlayer_ChangeTeam,     "CBasePlayer::ChangeTeam [int, bool, bool, bool]");
			MOD_ADD_DETOUR_MEMBER(CBaseEntity_ChangeTeam,     "CBaseEntity::ChangeTeam");
			MOD_ADD_DETOUR_MEMBER(CTFTeam_AddPlayer,        "CTFTeam::AddPlayer");
			MOD_ADD_DETOUR_MEMBER(CTFTeam_RemovePlayer,     "CTFTeam::RemovePlayer");
			MOD_ADD_DETOUR_MEMBER(CTFPlayer_UpdateOnRemove, "CTFPlayer::UpdateOnRemove");
		}
	};
	CMod s_Mod;

	ConVar cvar_enable("sig_debug_team_lists", "0", FCVAR_NOTIFY,
		"Debug: report a team list that gains a player twice or keeps a removed one, with the stack",
		[](IConVar *pConVar, const char *pOldValue, float flOldValue){
			s_Mod.Toggle(static_cast<ConVar *>(pConVar)->GetBool());
		});
}
