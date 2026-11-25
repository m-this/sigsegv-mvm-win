#include "mod.h"
#include "stub/tfbot.h"
#include "mem/extract.h"

namespace Mod::Robot::Underground_Check_Override
{
	constexpr uint8_t s_Buf[] = {
#ifdef PLATFORM_64BITS
		0x66, 0x41, 0x0f, 0x6e, 0xc7,                                // +0x0000 movd    xmm0, r15d
		0xf3, 0x41, 0x0f, 0x5c, 0x84, 0x24, 0xcc, 0x03, 0x00, 0x00,  // +0x0005 subss   xmm0, dword ptr [r12+3CCh]
		0x0f, 0x2f, 0x05, 0xb8, 0x10, 0x47, 0x00,                    // +0x000f comiss  xmm0, cs:dword_148CEC8
		0x0f, 0x86, 0x52, 0x02, 0x00, 0x00,                          // +0x0016 jbe     loc_101C068
		0x66, 0x0f, 0xef, 0xc0,                                      // +0x001c pxor    xmm0, xmm0
		0x41, 0x0f, 0x2f, 0x86, 0xac, 0x00, 0x00, 0x00,              // +0x0020 comiss  xmm0, dword ptr [r14+0ACh]
#else
		0xf3, 0x0f, 0x5c, 0x87, 0x00, 0x00, 0x00, 0x00,  // +0x0000 subss   xmm0, dword ptr [edi+m_vecAbsOrigin.z]
		0x0f, 0x2f, 0x45, 0x90,                          // +0x0008 comiss  xmm0, dword ptr [ebp-70h]
		0x0f, 0x86, 0x00, 0x00, 0x00, 0x00,              // +0x000c jbe     not underground
		0x8b, 0x45, 0x0c,                                // +0x0012 mov     eax, [ebp+0Ch]
		0x66, 0x0f, 0xef, 0xc0,                          // +0x0015 pxor    xmm0, xmm0
		0xf3, 0x0f, 0x10, 0x48, 0x70,                    // +0x0019 movss   xmm1, dword ptr [eax+m_itUnderground]
#endif
	};

#if defined _WINDOWS
	/* MSVC subtracts the origin's z on the x87 stack after the nav area's
	 * GetZ, then reads the timer into xmm0 */
	constexpr uint8_t s_Buf_Windows[] = {
		0xd8, 0x60, 0x08,                                // +0x0000 fsub    dword ptr [eax+8]
		0xd9, 0x05, 0x00, 0x00, 0x00, 0x00,              // +0x0003 fld     dword ptr [100.0f]
		0xd9, 0xc9,                                      // +0x0009 fxch    st(1)
		0xdf, 0xf1,                                      // +0x000b fcomip  st, st(1)
		0xdd, 0xd8,                                      // +0x000d fstp    st(0)
		0x0f, 0x86, 0x00, 0x00, 0x00, 0x00,              // +0x000f jbe     not underground
		0xf3, 0x0f, 0x10, 0x47, 0x70,                    // +0x0015 movss   xmm0, dword ptr [edi+m_itUnderground]
		0x0f, 0x2f, 0x05, 0x00, 0x00, 0x00, 0x00,        // +0x001a comiss  xmm0, ds:[0.0f]
	};
#endif

#ifdef PLATFORM_64BITS
	using m_itUnderground_ptrsize = int32_t;
#else
	using m_itUnderground_ptrsize = int8_t;
#endif

	struct CExtract_CTFBotMainAction_m_itUnderground : public IExtract<m_itUnderground_ptrsize>
	{
#if defined _WINDOWS
		CExtract_CTFBotMainAction_m_itUnderground() : IExtract<m_itUnderground_ptrsize>(sizeof(s_Buf_Windows)) {}
		
		virtual bool GetExtractInfo(ByteBuf& buf, ByteBuf& mask) const override
		{
			buf.CopyFrom(s_Buf_Windows);
			
			mask.SetRange(0x03 + 2, 4, 0x00);
			mask.SetRange(0x0f + 2, 4, 0x00);
			mask.SetRange(0x15 + 4, 1, 0x00);
			mask.SetRange(0x1a + 3, 4, 0x00);
			
			return true;
		}
		
		virtual const char *GetFuncName() const override            { return "CTFBotMainAction::Update"; }
		virtual uint32_t GetFuncOffMin() const override             { return 0x0000; }
		virtual uint32_t GetFuncOffMax() const override             { return 0x0600; } // @ 0x046b
		virtual uint32_t GetExtractOffset() const override          { return 0x0015 + 4; }
#else
		CExtract_CTFBotMainAction_m_itUnderground() : IExtract<m_itUnderground_ptrsize>(sizeof(s_Buf)) {}
		
		virtual bool GetExtractInfo(ByteBuf& buf, ByteBuf& mask) const override
		{
			buf.CopyFrom(s_Buf);
			
			int off_m_vecAbsOrigin = 0;
			if (!Prop::FindOffset(off_m_vecAbsOrigin, "CBaseEntity", "m_vecAbsOrigin")) return false;
			
#ifdef PLATFORM_64BITS
			buf.SetDword(0x05 + 6, off_m_vecAbsOrigin + 8);
			
			mask.SetRange(0x0f + 3, 4, 0x00);
			mask.SetRange(0x16 + 2, 4, 0x00);
			mask.SetRange(0x20 + 4, 4, 0x00);
#else
			buf.SetDword(0x00 + 4, off_m_vecAbsOrigin + 8);
			
			mask.SetRange(0x00 + 3, 1, 0x00);
			mask.SetRange(0x08 + 2, 2, 0x00);
			mask.SetRange(0x0c + 2, 4, 0x00);
			mask.SetRange(0x12 + 2, 1, 0x00);
			mask.SetRange(0x19 + 4, 1, 0x00);
#endif
			
			return true;
		}
		
		virtual const char *GetFuncName() const override            { return "CTFBotMainAction::Update"; }
		virtual uint32_t GetFuncOffMin() const override             { return 0x0000; }
		virtual uint32_t GetFuncOffMax() const override             { return 0x0a00; } // @ 0x06fe
#ifdef PLATFORM_64BITS
		virtual uint32_t GetExtractOffset() const override          { return 0x0020 + 4; }
#else
		virtual uint32_t GetExtractOffset() const override          { return 0x0019 + 4; }
#endif
#endif
	};
	
	
	ptrdiff_t off_CTFBotMainAction_m_itUnderground = 0;
	
	
	RefCount rc_CTFBotMainAction_Update;
	DETOUR_DECL_MEMBER(ActionResult<CTFBot>, CTFBotMainAction_Update, CTFBot *actor, float dt)
	{
		auto m_itUnderground = reinterpret_cast<IntervalTimer *>((uintptr_t)this + off_CTFBotMainAction_m_itUnderground);
		m_itUnderground->Invalidate();
		
		return DETOUR_MEMBER_CALL(actor, dt);
	}
	
	
	class CMod : public IMod
	{
	public:
		CMod() : IMod("Robot:Underground_Check_Override")
		{
			MOD_ADD_DETOUR_MEMBER(CTFBotMainAction_Update, "CTFBotMainAction::Update");
		}
		
		virtual bool OnLoad() override
		{
			CExtract_CTFBotMainAction_m_itUnderground extractor;
			if (!extractor.Init())  return false;
			if (!extractor.Check()) return false;
			
			off_CTFBotMainAction_m_itUnderground = extractor.Extract();
		//	DevMsg("CTFBotMainAction::m_itUnderground @ +0x%02x\n", off_CTFBotMainAction_m_itUnderground);
			
			return true;
		}
	};
	CMod s_Mod;
	
	
	ConVar cvar_enable("sig_robot_underground_check_override", "0", FCVAR_NOTIFY,
		"Mod: disable the faulty underground-detection logic in CTFBotMainAction::Update",
		[](IConVar *pConVar, const char *pOldValue, float flOldValue){
			s_Mod.Toggle(static_cast<ConVar *>(pConVar)->GetBool());
		});
}
