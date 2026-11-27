#include "mod.h"
#include "stub/team.h"
#include "stub/tfplayer.h"

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
		if (team->m_aPlayers->Find(player) == -1) {
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

	class CMod : public IMod
	{
	public:
		CMod() : IMod("Debug:Team_Lists")
		{
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
