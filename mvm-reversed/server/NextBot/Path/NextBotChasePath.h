/* reverse engineering by sigsegv
 * based on TF2 version 20151007a
 * server/NextBot/Path/NextBotChasePath.h
 */


class ChasePath : public PathFollower
{
public:
	ChasePath(int chaseType) : PathFollower() {
		m_FailTimer.Invalidate();
		m_ctTimer2.Invalidate();
		m_ctTimer3.Invalidate();
		m_chaseType = chaseType;
#if defined _WINDOWS
		UseGameVTable();
#endif
	}
	virtual ~ChasePath() {};
	
#if defined _WINDOWS
	/* On Linux the mod's _ZTV9ChasePath is a copy of the game's. On Windows
	 * nothing replaces it, so a ChasePath the mod builds would keep the mod's
	 * vtable, whose slots are thunks that look the function up in that same
	 * vtable and call themselves forever. */
	void UseGameVTable();
#endif
	
	//virtual void Invalidate() override;
	
	virtual void Update(INextBot *nextbot, CBaseEntity *ent, const IPathCost& cost_func, Vector *vec);
	virtual float GetLeadRadius() const;
	virtual float GetMaxPathLength() const;
	virtual Vector PredictSubjectPosition(INextBot *nextbot, CBaseEntity *ent) const;
	virtual bool IsRepathNeeded(INextBot *nextbot, CBaseEntity *ent) const;
	virtual float GetLifetime() const;
	
	void RefreshPath(INextBot *nextbot, CBaseEntity *ent, const IPathCost& cost_func, Vector *vec);
	
	void ShortenFailTimer(float time) {
		if (!this->m_FailTimer.IsElapsed() && this->m_FailTimer.GetRemainingTime() > time) {
			this->m_FailTimer.Start(time);
		}
	}
protected:
	#define UNKNOWN_PTR void*
	#define PAD(n, x) char n[x]
	
	CountdownTimer m_FailTimer; // +0x47d8
	CountdownTimer m_ctTimer2; // +0x47e4
	CountdownTimer m_ctTimer3; // +0x47f0
	CHandle<CBaseEntity> m_hChaseSubject;
	int m_chaseType;
	// 47fc dword 0 or possibly 1
};

// TODO: DirectChasePath
