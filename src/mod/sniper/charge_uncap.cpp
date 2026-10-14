#include "mod.h"
#include "prop.h"


namespace Mod::Sniper::Charge_Uncap
{
#if defined _LINUX
	
	constexpr uint8_t s_Buf_CTFSniperRifle[] = {
		0xf3, 0x0f, 0x5f, 0xc1,                         // +0000  maxss xmm0,xmm1
		0xf3, 0x0f, 0x5d, 0x05, 0x30, 0x97, 0x2a, 0x01, // +0004  minss xmm0,[100.0f]
		0xf3, 0x0f, 0x11, 0x45, 0xc8,                   // +000C  movss [ebp-0x38],xmm0
		0xf3, 0x0f, 0x59, 0x40, 0x10,                   // +0011  mulss xmm0,dword ptr [eax+0x10]
		//0x8d, 0x83, 0x0C, 0x08, 0x00, 0x00,             // +0016  lea eax, dword ptr [ebx+m_flChargedDamage]
		//0xf3, 0x0f, 0x58, 0x83, 0xdc, 0x07, 0x00, 0x00, // +001c  addss xmm0,dword ptr [ebx+m_flChargedDamage]
		//0xc7, 0x44, 0x24, 0x08, 0x04, 0x00, 0x00, 0x00, // +0021  mov dword ptr [esp+8],4
		//0x89, 0x54, 0x24, 0x04,                         // +002C  mov [esp+4],edx
		//0x89, 0x04, 0x24,                               // +0030  mov [esp],eax
		//0xf3, 0x0f, 0x5d, 0x05, 0xb0, 0x75, 0x1b, 0x01, // +0033  minss xmm0,[150.0f]
	};
	
	struct CPatch_UncapChargeRate_CTFSniperRifle : public CPatch
	{
		CPatch_UncapChargeRate_CTFSniperRifle() : CPatch(sizeof(s_Buf_CTFSniperRifle)) {}
		
		virtual bool GetVerifyInfo(ByteBuf& buf, ByteBuf& mask) const override
		{
			buf.CopyFrom(s_Buf_CTFSniperRifle);
			
			//int off__CTFSniperRifle_m_flChargedDamage;
			//if (!Prop::FindOffset(off__CTFSniperRifle_m_flChargedDamage, "CTFSniperRifle", "m_flChargedDamage")) return false;
			
			//buf.SetDword(0x16 + 2, (uint32_t)off__CTFSniperRifle_m_flChargedDamage);
			//buf.SetDword(0x1c + 4, (uint32_t)off__CTFSniperRifle_m_flChargedDamage);
			
			mask.SetRange(0x04 + 4, 4, 0x00);
			mask.SetRange(0x0c + 4, 1, 0x00);
			//mask.SetRange(0x33 + 4, 4, 0x00);
			
			return true;
		}
		
		virtual bool GetPatchInfo(ByteBuf& buf, ByteBuf& mask) const override
		{
			/* NOP out the MINSS instruction */
			buf .SetRange(0x04, 8, 0x90);
			mask.SetRange(0x04, 8, 0xff);
			return true;
		}
		
		virtual const char *GetFuncName() const override { return "CTFSniperRifle::ItemPostFrame"; }
		virtual uint32_t GetFuncOffMin() const override  { return 0x0000; }
		virtual uint32_t GetFuncOffMax() const override  { return 0x0480; } // @ 0x0424
	};
	
	constexpr uint8_t s_Buf_CTFSniperRifleClassic[] = {
		0xf3, 0x0f, 0x5f, 0xc1,                         // +0000  maxss xmm0,xmm1
		0xf3, 0x0f, 0x5d, 0x05, 0x90, 0xad, 0x1f, 0x01, // +0004  minss xmm0,[100.0f]
		0xf3, 0x0f, 0x11, 0x45, 0xc8,                   // +000C  movss [ebp-0x38],xmm0
		0xf3, 0x0f, 0x59, 0x40, 0x10,                   // +0011  mulss xmm0,dword ptr [eax+0x10]
		//0x8d, 0x83, 0xdc, 0x07, 0x00, 0x00,             // +0016  lea eax,[ebx+m_flChargedDamage]
		//0xf3, 0x0f, 0x58, 0x83, 0xdc, 0x07, 0x00, 0x00, // +001C  addss xmm0,dword ptr [ebx+m_flChargedDamage]
		//0xc7, 0x44, 0x24, 0x08, 0x04, 0x00, 0x00, 0x00, // +0024  mov dword ptr [esp+8],4
		//0x89, 0x54, 0x24, 0x04,                         // +002C  mov [esp+4],edx
		//0x89, 0x04, 0x24,                               // +0030  mov [esp],eax
		//0xf3, 0x0f, 0x5d, 0x05, 0xb0, 0x75, 0x1b, 0x01, // +0033  minss xmm0,[150.0f]
	};
	
	struct CPatch_UncapChargeRate_CTFSniperRifleClassic : public CPatch
	{
		CPatch_UncapChargeRate_CTFSniperRifleClassic() : CPatch(sizeof(s_Buf_CTFSniperRifleClassic)) {}
		
		virtual bool GetVerifyInfo(ByteBuf& buf, ByteBuf& mask) const override
		{
			buf.CopyFrom(s_Buf_CTFSniperRifleClassic);
			
			//int off__CTFSniperRifle_m_flChargedDamage;
			//if (!Prop::FindOffset(off__CTFSniperRifle_m_flChargedDamage, "CTFSniperRifle", "m_flChargedDamage")) return false;
			
			//buf.SetDword(0x16 + 2, (uint32_t)off__CTFSniperRifle_m_flChargedDamage);
			//buf.SetDword(0x1c + 4, (uint32_t)off__CTFSniperRifle_m_flChargedDamage);
			
			mask.SetRange(0x04 + 4, 4, 0x00);
			mask.SetRange(0x0c + 4, 1, 0x00);
			//mask.SetRange(0x33 + 4, 4, 0x00);
			
			return true;
		}
		
		virtual bool GetPatchInfo(ByteBuf& buf, ByteBuf& mask) const override
		{
			/* NOP out the MINSS instruction */
			buf .SetRange(0x04, 8, 0x90);
			mask.SetRange(0x04, 8, 0xff);
			
			return true;
		}
		
		virtual const char *GetFuncName() const override { return "CTFSniperRifleClassic::ItemPostFrame"; }
		virtual uint32_t GetFuncOffMin() const override  { return 0x0000; }
		virtual uint32_t GetFuncOffMax() const override  { return 0x0280; } // @ 0x0141
	};
	
#elif defined _WINDOWS
	
	constexpr uint8_t s_Buf[] = {
		0xf3, 0x0f, 0x5f, 0xd8,                         // +0000  maxss xmm3,xmm0
		0xf3, 0x0f, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, // +0004  movss xmm0,DWORD PTR [100.0f]
		0xf3, 0x0f, 0x5d, 0xd8,                         // +000C  minss xmm3,xmm0
		0xf3, 0x0f, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, // +0010  movss xmm0,DWORD PTR [xxxxxxxx]
		0xf3, 0x0f, 0x59, 0x58, 0x10,                   // +0018  mulss xmm3,dword ptr [eax+0x10]
	};
	
	struct CPatch_UncapChargeRate_Common : public CPatch
	{
		CPatch_UncapChargeRate_Common() : CPatch(sizeof(s_Buf)) {}
		
		virtual bool GetVerifyInfo(ByteBuf& buf, ByteBuf& mask) const override
		{
			buf.CopyFrom(s_Buf);
			
			mask.SetRange(0x04 + 4, 4, 0x00);
			mask.SetRange(0x10 + 4, 4, 0x00);
			
			return true;
		}
		
		virtual bool GetPatchInfo(ByteBuf& buf, ByteBuf& mask) const override
		{
			/* NOP out the MINSS instruction */
			buf.SetRange(0x0c, 4, 0x90);
			mask.SetRange(0x0c, 4, 0xff);
			
			return true;
		}
	};
	
	struct CPatch_UncapChargeRate_CTFSniperRifle : public CPatch_UncapChargeRate_Common
	{
		virtual const char *GetFuncName() const override { return "CTFSniperRifle::ItemPostFrame"; }
		virtual uint32_t GetFuncOffMin() const override  { return 0x0000; }
		virtual uint32_t GetFuncOffMax() const override  { return 0x0200; } // @ 0x15b
	};
	
	struct CPatch_UncapChargeRate_CTFSniperRifleClassic : CPatch_UncapChargeRate_Common
	{
		virtual const char *GetFuncName() const override { return "CTFSniperRifleClassic::ItemPostFrame"; }
		virtual uint32_t GetFuncOffMin() const override  { return 0x0000; }
		virtual uint32_t GetFuncOffMax() const override  { return 0x0200; } // @ 0x157
	};
	
#endif
	
	
	class CMod : public IMod
	{
	public:
		CMod() : IMod("Sniper:Charge_Uncap")
		{
			this->AddPatch(new CPatch_UncapChargeRate_CTFSniperRifle());
			this->AddPatch(new CPatch_UncapChargeRate_CTFSniperRifleClassic());
		}
	};
	CMod s_Mod;
	
	
	ConVar cvar_enable("sig_sniper_charge_uncap", "0", FCVAR_NOTIFY,
		"Mod: remove the 200 percent upper limit on sniper rifle charge rate",
		[](IConVar *pConVar, const char *pOldValue, float flOldValue){
			s_Mod.Toggle(static_cast<ConVar *>(pConVar)->GetBool());
		});
}
