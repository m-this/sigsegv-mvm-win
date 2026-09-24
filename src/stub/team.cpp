#include "stub/team.h"


MemberVFuncThunk<const CTeam *, int>                CTeam::vt_GetTeamNumber(TypeName<CTeam>(), "CTeam::GetTeamNumber");
MemberVFuncThunk<      CTeam *, const char *>       CTeam::vt_GetName      (TypeName<CTeam>(), "CTeam::GetName");
MemberVFuncThunk<      CTeam *, int>                CTeam::vt_GetNumPlayers(TypeName<CTeam>(), "CTeam::GetNumPlayers");
MemberVFuncThunk<      CTeam *, CBasePlayer *, int> CTeam::vt_GetPlayer    (TypeName<CTeam>(), "CTeam::GetPlayer");

MemberFuncThunk<      CTeam *, void, CBasePlayer *> CTeam::ft_AddPlayer    ("CTeam::AddPlayer");
MemberFuncThunk<      CTeam *, void, CBasePlayer *> CTeam::ft_RemovePlayer ("CTeam::RemovePlayer");

IMPL_SENDPROP(char[32], CTeam, m_szTeamname, CTeam);
IMPL_REL_BEFORE(CUtlVector<CBasePlayer *>, CTeam, m_aPlayers, m_szTeamname, 0);

#ifdef SE_IS_TF2
MemberFuncThunk<CTFTeam *, int, int>           CTFTeam::ft_GetNumObjects("CTFTeam::GetNumObjects");
MemberFuncThunk<CTFTeam *, CBaseObject *, int> CTFTeam::ft_GetObject    ("CTFTeam::GetObject");

IMPL_SENDPROP(CHandle<CBasePlayer>, CTFTeam, m_hLeader, CTFTeam);


MemberFuncThunk<CTFTeamManager *, bool, int>      CTFTeamManager::ft_IsValidTeam("CTFTeamManager::IsValidTeam");
MemberFuncThunk<CTFTeamManager *, CTFTeam *, int> CTFTeamManager::ft_GetTeam    ("CTFTeamManager::GetTeam");

GlobalThunk<CTFTeamManager> s_TFTeamManager("s_TFTeamManager");

#if defined _WINDOWS
CTFTeam *CTFTeamManager::GetTeam(int iTeam)
{
	static CHandle<CBaseEntity> cache[8];
	if (iTeam < 0 || iTeam >= (int)ARRAYSIZE(cache)) return nullptr;
	
	CBaseEntity *team = cache[iTeam];
	if (team == nullptr || team->GetTeamNumber() != iTeam) {
		team = nullptr;
		for (CBaseEntity *ent = servertools->FindEntityByClassname(nullptr, "tf_team"); ent != nullptr; ent = servertools->FindEntityByClassname(ent, "tf_team")) {
			if (ent->GetTeamNumber() == iTeam) { team = ent; break; }
		}
		cache[iTeam] = team;
	}
	return static_cast<CTFTeam *>(team);
}
#endif

#endif