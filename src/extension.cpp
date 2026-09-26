#include "extension.h"
#include "library.h"
#include "link/link.h"
#include "mem/alloc.h"
#include "mod.h"
#include "addr/addr.h"
#include "addr/prescan.h"
#include "stub/baseplayer.h"
#include "gameconf.h"
#include "prop.h"
#include "util/pooled_string.h"
#include "util/rtti.h"
//#include "disasm/disasm.h"
#include "factory.h"
#include "concolor.h"
#ifdef SE_IS_TF2
#include "re/nextbot.h"
#endif
#include "version.h"
#include "convar_restore.h"
#ifdef SE_IS_TF2
#include "vscript/ivscript.h"
#endif
//#include "entity.h"

CExtSigsegv g_Ext;
SMEXT_LINK(&g_Ext);

IFileSystem *filesystem                          = nullptr;
IServerGameClients *serverGameClients            = nullptr;
IServerGameEnts *serverGameEnts                  = nullptr;
ICvar *icvar                                     = nullptr;
IServer *sv                                      = nullptr;
ISpatialPartition *partition                     = nullptr;
IEngineTrace *enginetrace                        = nullptr;
IStaticPropMgrServer *staticpropmgr              = nullptr;
IGameEventManager2 *gameeventmanager             = nullptr;
INetworkStringTableContainer *networkstringtable = nullptr;
IEngineSound *enginesound                        = nullptr;
IVModelInfo *modelinfo                           = nullptr;
IVDebugOverlay *debugoverlay                     = nullptr;

IPlayerInfoManager *playerinfomanager = nullptr;
IBotManager *botmanager               = nullptr;

IPhysics *physics                = nullptr;
IPhysicsCollision *physcollision = nullptr;
IPhysicsSurfaceProps *physprops  = nullptr;

ISoundEmitterSystemBase *soundemitterbase = nullptr;

IMaterialSystem *g_pMaterialSystem = nullptr;

vgui::IVGui *g_pVGui                       = nullptr;
vgui::IInput *g_pVGuiInput                 = nullptr;
vgui::IPanel *g_pVGuiPanel                 = nullptr;
vgui::ISchemeManager *g_pVGuiSchemeManager = nullptr;
vgui::ISystem *g_pVGuiSystem               = nullptr;
vgui::ILocalize *g_pVGuiLocalize           = nullptr;
vgui::IInputInternal *g_pVGuiInputInternal = nullptr;

vgui::ISurface *g_pVGuiSurface         = nullptr;
IMatSystemSurface *g_pMatSystemSurface = nullptr;

CGlobalVars *gpGlobals         = nullptr;
CGlobalEntityList *gEntList    = nullptr;
CBaseEntityList *g_pEntityList = nullptr;

IVEngineClient *engineclient     = nullptr;
IBaseClientDLL *clientdll        = nullptr;
IClientEntityList *cl_entitylist = nullptr;

IEngineTool *enginetools  = nullptr;
IServerTools *servertools = nullptr;
IClientTools *clienttools = nullptr;
IGameMovement *g_pGameMovement = nullptr;

IVProfExport *vprofexport = nullptr;

IDedicatedExports *dedicated = nullptr;

IMDLCache *mdlcache = nullptr;

IClientMode *g_pClientMode = nullptr;

IPhraseCollection *phrases = nullptr;
IPhraseFile *phrasesFile = nullptr;
IPhraseCollection *phrasesAttribs = nullptr;
IPhraseFile *phrasesAttribsFile = nullptr;

IScriptManager *scriptManager = nullptr;

extern int laserSprite;
#if defined _WINDOWS
#include <psapi.h>
#include <intrin.h>

/* Who ends the server. The engine's Error() leaves through tier0's
 * Plat_ExitProcess, TerminateProcess on itself with status 100, and on
 * Windows its message never reaches console.log: a server that died that way
 * looked like one that simply stopped. Every loaded module's imports of
 * TerminateProcess and ExitProcess are pointed here, which writes the calling
 * stack as module+offset to sigsegv_exit.txt in the game directory and to the
 * console, then does what was asked. */
/* Frames the main thread has run, counted by CModManager for the watchdog. */
volatile LONG g_WatchdogFrames = 0;

/* For the bed: whose memory the servers run out of. Every module compiles the
 * SDK's memoverride, which allocates through tier0's g_pMemAlloc, so SigMod
 * and the game share one heap and its growth names nobody. This stands in
 * front of the real allocator, forwards every call, and counts the bytes each
 * calling module allocates and frees; a leak is the module whose balance
 * climbs across missions. */
namespace MemCount
{
	struct Module { const char *name; uintptr_t base = 0, end = 0; volatile LONG64 net = 0; };
	Module modules[] = {
		{ "sigsegv.ext.2.tf2.dll" }, { "server.dll" }, { "engine.dll" }, { "sourcemod.2.tf2.dll" },
		{ "sourcepawn.jit.x86.dll" }, { "datacache.dll" }, { "materialsystem.dll" }, { "vstdlib.dll" },
		{ "other" },
	};
	constexpr int count = sizeof(modules) / sizeof(modules[0]);
	
	Module &Of(void *ret)
	{
		auto at = reinterpret_cast<uintptr_t>(ret);
		for (int i = 0; i < count - 1; ++i) {
			if (at >= modules[i].base && at < modules[i].end) return modules[i];
		}
		return modules[count - 1];
	}
	
	class Proxy : public IMemAlloc
	{
	public:
		IMemAlloc *real = nullptr;
		
		void Add(void *ret, void *p)    { if (p != nullptr) InterlockedAdd64(&Of(ret).net,  (LONG64)real->GetSize(p)); }
		void Remove(void *ret, void *p) { if (p != nullptr) InterlockedAdd64(&Of(ret).net, -(LONG64)real->GetSize(p)); }
		
		virtual void *Alloc(size_t n) override                                  { void *p = real->Alloc(n); Add(_ReturnAddress(), p); return p; }
		virtual void *Realloc(void *m, size_t n) override                       { Remove(_ReturnAddress(), m); void *p = real->Realloc(m, n); Add(_ReturnAddress(), p); return p; }
		virtual void Free(void *m) override                                     { Remove(_ReturnAddress(), m); real->Free(m); }
		virtual void *Expand_NoLongerSupported(void *m, size_t n) override      { return real->Expand_NoLongerSupported(m, n); }
		virtual void *Alloc(size_t n, const char *f, int l) override            { void *p = real->Alloc(n, f, l); Add(_ReturnAddress(), p); return p; }
		virtual void *Realloc(void *m, size_t n, const char *f, int l) override { Remove(_ReturnAddress(), m); void *p = real->Realloc(m, n, f, l); Add(_ReturnAddress(), p); return p; }
		virtual void Free(void *m, const char *f, int l) override               { Remove(_ReturnAddress(), m); real->Free(m, f, l); }
		virtual void *Expand_NoLongerSupported(void *m, size_t n, const char *f, int l) override { return real->Expand_NoLongerSupported(m, n, f, l); }
		virtual size_t GetSize(void *m) override                                { return real->GetSize(m); }
		virtual void PushAllocDbgInfo(const char *f, int l) override            { real->PushAllocDbgInfo(f, l); }
		virtual void PopAllocDbgInfo() override                                 { real->PopAllocDbgInfo(); }
		virtual long CrtSetBreakAlloc(long b) override                          { return real->CrtSetBreakAlloc(b); }
		virtual int CrtSetReportMode(int t, int m) override                     { return real->CrtSetReportMode(t, m); }
		virtual int CrtIsValidHeapPointer(const void *m) override               { return real->CrtIsValidHeapPointer(m); }
		virtual int CrtIsValidPointer(const void *m, unsigned int s, int a) override { return real->CrtIsValidPointer(m, s, a); }
		virtual int CrtCheckMemory() override                                   { return real->CrtCheckMemory(); }
		virtual int CrtSetDbgFlag(int f) override                               { return real->CrtSetDbgFlag(f); }
		virtual void CrtMemCheckpoint(_CrtMemState *s) override                 { real->CrtMemCheckpoint(s); }
		virtual void DumpStats() override                                       { real->DumpStats(); }
		virtual void DumpStatsFileBase(char const *b) override                  { real->DumpStatsFileBase(b); }
		virtual void *CrtSetReportFile(int t, void *h) override                 { return real->CrtSetReportFile(t, h); }
		virtual void *CrtSetReportHook(void *h) override                        { return real->CrtSetReportHook(h); }
		virtual int CrtDbgReport(int t, const char *f, int l, const char *m, const char *msg) override { return real->CrtDbgReport(t, f, l, m, msg); }
		virtual int heapchk() override                                          { return real->heapchk(); }
		virtual bool IsDebugHeap() override                                     { return real->IsDebugHeap(); }
		virtual void GetActualDbgInfo(const char *&f, int &l) override          { real->GetActualDbgInfo(f, l); }
		virtual void RegisterAllocation(const char *f, int l, int a, int b, unsigned t) override   { real->RegisterAllocation(f, l, a, b, t); }
		virtual void RegisterDeallocation(const char *f, int l, int a, int b, unsigned t) override { real->RegisterDeallocation(f, l, a, b, t); }
		virtual int GetVersion() override                                       { return real->GetVersion(); }
		virtual void CompactHeap() override                                     { real->CompactHeap(); }
		virtual MemAllocFailHandler_t SetAllocFailHandler(MemAllocFailHandler_t h) override { return real->SetAllocFailHandler(h); }
		virtual void DumpBlockStats(void *p) override                           { real->DumpBlockStats(p); }
#if defined( _MEMTEST )
		virtual void SetStatsExtraInfo(const char *m, const char *c) override   { real->SetStatsExtraInfo(m, c); }
#endif
		virtual size_t MemoryAllocFailed() override                             { return real->MemoryAllocFailed(); }
		virtual uint32 GetDebugInfoSize() override                              { return real->GetDebugInfoSize(); }
		virtual void SaveDebugInfo(void *d) override                            { real->SaveDebugInfo(d); }
		virtual void RestoreDebugInfo(const void *d) override                   { real->RestoreDebugInfo(d); }
		virtual void InitDebugInfo(void *d, const char *f, int l) override      { real->InitDebugInfo(d, f, l); }
		virtual void GlobalMemoryStatus(size_t *u, size_t *f) override          { real->GlobalMemoryStatus(u, f); }
	};
	Proxy proxy;
	
	void Install()
	{
		for (int i = 0; i < count - 1; ++i) {
			HMODULE mod = GetModuleHandleA(modules[i].name);
			MODULEINFO info;
			if (mod != nullptr && GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(info))) {
				modules[i].base = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
				modules[i].end  = modules[i].base + info.SizeOfImage;
			}
		}
		proxy.real = g_pMemAlloc;
		g_pMemAlloc = &proxy;
	}
	
	void Report(char *out, size_t size)
	{
		size_t len = 0;
		out[0] = '\0';
		for (int i = 0; i < count && len < size - 48; ++i) {
			LONG64 net = modules[i].net;
			if (net > -(LONG64(1) << 20) && net < (LONG64(1) << 20)) continue;
			len += snprintf(out + len, size - len, " %s %+lld MB", modules[i].name, (long long)(net >> 20));
		}
	}
}

namespace ExitTrace
{
	using TerminateProcess_t = BOOL (WINAPI *)(HANDLE, UINT);
	using ExitProcess_t      = void (WINAPI *)(UINT);
	TerminateProcess_t RealTerminateProcess = nullptr;
	ExitProcess_t      RealExitProcess      = nullptr;
	
	/* An address as module+offset, the way the bed report names frames. */
	void Name(char *out, size_t size, const void *addr)
	{
		HMODULE mod = nullptr;
		char path[MAX_PATH] = "?";
		if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(addr), &mod) && mod != nullptr) {
			GetModuleFileNameA(mod, path, sizeof(path));
		}
		const char *base = strrchr(path, '\\');
		snprintf(out, size, "%s+0x%x", base != nullptr ? base + 1 : path,
			mod != nullptr ? (unsigned)((uintptr_t)addr - (uintptr_t)mod) : (unsigned)(uintptr_t)addr);
	}
	
	void Write(const char *header, void *const *frames, int n)
	{
		FILE *f = fopen("sigsegv_exit.txt", "a");
		if (f != nullptr) fputs(header, f);
		Warning("%s", header);
		char line[512], name[MAX_PATH + 16];
		for (int i = 0; i < n; ++i) {
			Name(name, sizeof(name), frames[i]);
			snprintf(line, sizeof(line), "  %s\n", name);
			if (f != nullptr) fputs(line, f);
			Warning("%s", line);
		}
		if (f != nullptr) fclose(f);
	}
	
	void Write(const char *what, UINT code)
	{
		void *frames[48];
		USHORT n = RtlCaptureStackBackTrace(2, 48, frames, nullptr);
		char header[128];
		snprintf(header, sizeof(header), "SigMod: %s(%u) called from:\n", what, code);
		Write(header, frames, n);
	}
	
	bool Readable(const void *p, size_t len)
	{
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT) return false;
		if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
		return (uintptr_t)p + len <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
	}
	
	/* The faults that end a server: an access violation, or a jump into data.
	 * The handler sees them first-chance, before whatever catches them, so it
	 * records the first few and passes every one on untouched. The frames are
	 * the EBP chain, which is what the game's own code keeps. */
	LONG CALLBACK OnFault(EXCEPTION_POINTERS *info)
	{
		static LONG recorded = 0;
		DWORD code = info->ExceptionRecord->ExceptionCode;
		if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_PRIV_INSTRUCTION && code != EXCEPTION_ILLEGAL_INSTRUCTION) return EXCEPTION_CONTINUE_SEARCH;
		if (InterlockedIncrement(&recorded) > 8) return EXCEPTION_CONTINUE_SEARCH;
		
		const CONTEXT *ctx = info->ContextRecord;
		void *frames[40];
		int n = 0;
		frames[n++] = reinterpret_cast<void *>(ctx->Eip);
		auto ebp = reinterpret_cast<const uintptr_t *>(ctx->Ebp);
		while (n < 40 && ebp != nullptr && Readable(ebp, 8)) {
			if (ebp[1] == 0) break;
			frames[n++] = reinterpret_cast<void *>(ebp[1]);
			auto next = reinterpret_cast<const uintptr_t *>(ebp[0]);
			if (next <= ebp) break;
			ebp = next;
		}
		char name[MAX_PATH + 16], header[MAX_PATH + 160];
		Name(name, sizeof(name), reinterpret_cast<void *>(ctx->Eip));
		ULONG_PTR target = info->ExceptionRecord->NumberParameters >= 2 ? info->ExceptionRecord->ExceptionInformation[1] : 0;
		snprintf(header, sizeof(header), "SigMod: fault 0x%08lx at %s touching 0x%08lx (esp 0x%08lx), EBP chain:\n",
			code, name, (unsigned long)target, (unsigned long)ctx->Esp);
		Write(header, frames, n);
		
		/* A return into an argument (eip=1) leaves no chain: EBP was already
		 * popped. The words just above ESP still hold the return addresses of
		 * the frames that were running, so name the ones that point into
		 * code, closest first. */
		auto esp = reinterpret_cast<void *const *>(ctx->Esp);
		FILE *f = fopen("sigsegv_exit.txt", "a");
		char line[MAX_PATH + 64];
		/* Each register, where it points, and for one that points at an
		 * object, its first word (a vtable) and that table's slots 0x64 and
		 * 0x68: a call through a bad slot is read off these. */
		const struct { const char *name; DWORD value; } regs[] = {
			{"eax", ctx->Eax}, {"ebx", ctx->Ebx}, {"ecx", ctx->Ecx}, {"edx", ctx->Edx},
			{"esi", ctx->Esi}, {"edi", ctx->Edi}, {"ebp", ctx->Ebp},
		};
		for (const auto &r : regs) {
			char where[MAX_PATH + 16], vt[MAX_PATH + 16] = "-";
			Name(where, sizeof(where), reinterpret_cast<void *>(r.value));
			auto obj = reinterpret_cast<void *const *>(r.value);
			unsigned long w0 = 0, s64 = 0, s68 = 0;
			if (Readable(obj, sizeof(void *))) {
				w0 = (unsigned long)(uintptr_t)obj[0];
				Name(vt, sizeof(vt), obj[0]);
				auto table = reinterpret_cast<void *const *>(obj[0]);
				if (Readable(table + 0x68 / 4, sizeof(void *))) {
					s64 = (unsigned long)(uintptr_t)table[0x64 / 4];
					s68 = (unsigned long)(uintptr_t)table[0x68 / 4];
				}
			}
			snprintf(line, sizeof(line), "  %s 0x%08lx %s -> 0x%08lx %s [+0x64] 0x%08lx [+0x68] 0x%08lx\n",
				r.name, (unsigned long)r.value, where, w0, vt, s64, s68);
			if (f != nullptr) fputs(line, f);
			Warning("%s", line);
		}
		/* The words the bad ret left: the one it popped sat just below ESP. */
		for (int i = -2; i < 8; ++i) {
			if (!Readable(esp + i, sizeof(void *))) continue;
			snprintf(line, sizeof(line), "  [esp%+d] 0x%08lx\n", i * 4, (unsigned long)(uintptr_t)esp[i]);
			if (f != nullptr) fputs(line, f);
			Warning("%s", line);
		}
		int m = 0;
		for (int i = 0; i < 256 && m < 24 && Readable(esp + i, sizeof(void *)); ++i) {
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQuery(esp[i], &mbi, sizeof(mbi)) != 0 && mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE
				&& (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
				Name(name, sizeof(name), esp[i]);
				snprintf(line, sizeof(line), "  [esp+0x%x] %s\n", i * 4, name);
				if (f != nullptr) fputs(line, f);
				Warning("%s", line);
				++m;
			}
		}
		if (f != nullptr) fclose(f);
		return EXCEPTION_CONTINUE_SEARCH;
	}
	
	BOOL WINAPI HookTerminateProcess(HANDLE process, UINT code)
	{
		if (process == GetCurrentProcess() || GetProcessId(process) == GetCurrentProcessId()) Write("TerminateProcess", code);
		return RealTerminateProcess(process, code);
	}
	
	void WINAPI HookExitProcess(UINT code)
	{
		Write("ExitProcess", code);
		RealExitProcess(code);
	}
	
	/* Point one module's import of target at hook, wherever it imports it from. */
	void PatchImports(HMODULE mod, void *target, void *hook)
	{
		auto base = reinterpret_cast<uint8_t *>(mod);
		auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
		auto nt = reinterpret_cast<IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
		const IMAGE_DATA_DIRECTORY &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (dir.VirtualAddress == 0) return;
		for (auto imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(base + dir.VirtualAddress); imp->Name != 0; ++imp) {
			for (auto thunk = reinterpret_cast<IMAGE_THUNK_DATA *>(base + imp->FirstThunk); thunk->u1.Function != 0; ++thunk) {
				if (reinterpret_cast<void *>(thunk->u1.Function) != target) continue;
				DWORD old;
				if (VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), PAGE_READWRITE, &old)) {
					thunk->u1.Function = reinterpret_cast<uintptr_t>(hook);
					VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), old, &old);
				}
			}
		}
	}
	
	/* For the bed: a server that stops without faulting. The main thread's
	 * frames are counted by CModManager; when none has come for 45 seconds,
	 * a second thread suspends it, reads its EBP chain and the code addresses
	 * on its stack, resumes it, and only then prints, so a lock the main
	 * thread holds cannot hang the report too. A map load stalls frames as
	 * well; the report is capped at three. */
	HANDLE MainThread = nullptr;
	
	/* For the bed: servers end in "Out of memory or address space" a few
	 * missions in. Once a minute, what the process holds and what is left of
	 * its address space, so a leak reads as a climb across missions and a
	 * spike as one mission. */
	void ReportMemory()
	{
		PROCESS_MEMORY_COUNTERS_EX pmc = {};
		pmc.cb = sizeof(pmc);
		GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&pmc), sizeof(pmc));
		size_t free_total = 0, free_largest = 0, reserved = 0;
		/* Committed private memory by the size of the allocation it belongs
		 * to, in powers of two from 64 KB: a leak of one kind of allocation
		 * climbs in one class. */
		size_t by_class[16] = {}, count_class[16] = {};
		void *base = nullptr;
		size_t base_committed = 0;
		auto close_base = [&]() {
			if (base_committed == 0) return;
			int c = 0;
			while (c < 15 && (size_t(0x10000) << c) < base_committed) ++c;
			by_class[c] += base_committed;
			++count_class[c];
			base_committed = 0;
		};
		MEMORY_BASIC_INFORMATION mbi;
		for (uintptr_t at = 0x10000; VirtualQuery(reinterpret_cast<void *>(at), &mbi, sizeof(mbi)) != 0; ) {
			if (mbi.AllocationBase != base) { close_base(); base = mbi.AllocationBase; }
			if (mbi.State == MEM_FREE) {
				free_total += mbi.RegionSize;
				if (mbi.RegionSize > free_largest) free_largest = mbi.RegionSize;
			} else if (mbi.State == MEM_RESERVE) {
				reserved += mbi.RegionSize;
			} else if (mbi.Type == MEM_PRIVATE) {
				base_committed += mbi.RegionSize;
			}
			uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
			if (next <= at) break;
			at = next;
		}
		close_base();
		char classes[512] = "";
		size_t len = 0;
		for (int c = 0; c < 16 && len < sizeof(classes) - 40; ++c) {
			if (by_class[c] < (size_t(16) << 20)) continue;
			len += snprintf(classes + len, sizeof(classes) - len, " %uK:%ux=%uMB",
				(unsigned)((size_t(0x10000) << c) >> 10), (unsigned)count_class[c], (unsigned)(by_class[c] >> 20));
		}
		char owners[512];
		MemCount::Report(owners, sizeof(owners));
		Warning("SigMod: memory: private %u MB, working set %u MB, reserved %u MB, free %u MB, largest free %u MB; by allocation size:%s; net since load by caller:%s\n",
			(unsigned)(pmc.PrivateUsage >> 20), (unsigned)(pmc.WorkingSetSize >> 20), (unsigned)(reserved >> 20),
			(unsigned)(free_total >> 20), (unsigned)(free_largest >> 20), classes, owners);
	}
	
	DWORD WINAPI Watchdog(void *)
	{
		LONG last = g_WatchdogFrames;
		int still = 0, reports = 0, ticks = 0;
		bool reported = false;
		for (;;) {
			Sleep(5000);
			if (++ticks % 12 == 0) ReportMemory();
			if (reports >= 3) continue;
			LONG now = g_WatchdogFrames;
			if (now != last || now == 0) { last = now; still = 0; reported = false; continue; }
			if ((still += 5) < 45 || reported) continue;
			
			void *frames[40], *stack[24];
			int n = 0, m = 0;
			CONTEXT ctx = {};
			ctx.ContextFlags = CONTEXT_FULL;
			if (SuspendThread(MainThread) == (DWORD)-1) continue;
			if (GetThreadContext(MainThread, &ctx)) {
				frames[n++] = reinterpret_cast<void *>(ctx.Eip);
				auto ebp = reinterpret_cast<const uintptr_t *>(ctx.Ebp);
				while (n < 40 && ebp != nullptr && Readable(ebp, 8)) {
					if (ebp[1] == 0) break;
					frames[n++] = reinterpret_cast<void *>(ebp[1]);
					auto next = reinterpret_cast<const uintptr_t *>(ebp[0]);
					if (next <= ebp) break;
					ebp = next;
				}
				auto esp = reinterpret_cast<void *const *>(ctx.Esp);
				for (int i = 0; i < 512 && m < 24 && Readable(esp + i, sizeof(void *)); ++i) {
					MEMORY_BASIC_INFORMATION mbi;
					if (VirtualQuery(esp[i], &mbi, sizeof(mbi)) != 0 && mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE
						&& (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
						stack[m++] = esp[i];
					}
				}
			}
			ResumeThread(MainThread);
			if (n == 0) continue;
			
			char name[MAX_PATH + 16], header[MAX_PATH + 160];
			Name(name, sizeof(name), frames[0]);
			snprintf(header, sizeof(header), "SigMod: stall %d s without a frame, main thread at %s, EBP chain:\n", still, name);
			Write(header, frames, n);
			snprintf(header, sizeof(header), "SigMod: stall code addresses on the main thread's stack:\n");
			Write(header, stack, m);
			reported = true;
			++reports;
		}
	}
	
	void Install()
	{
		AddVectoredExceptionHandler(1, &OnFault);
		if (getenv("SIGSEGV_SURVEY_UNRESOLVED") != nullptr) MemCount::Install();
		if (getenv("SIGSEGV_SURVEY_UNRESOLVED") != nullptr
			&& DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &MainThread, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
			CreateThread(nullptr, 0, &Watchdog, nullptr, 0, nullptr);
		}
		HMODULE k32 = GetModuleHandleA("kernel32.dll");
		HMODULE kb  = GetModuleHandleA("kernelbase.dll");
		if (k32 == nullptr) return;
		RealTerminateProcess = reinterpret_cast<TerminateProcess_t>(GetProcAddress(k32, "TerminateProcess"));
		RealExitProcess      = reinterpret_cast<ExitProcess_t>(GetProcAddress(k32, "ExitProcess"));
		if (RealTerminateProcess == nullptr || RealExitProcess == nullptr) return;
		void *targets[4][2] = {
			{ reinterpret_cast<void *>(RealTerminateProcess), reinterpret_cast<void *>(&HookTerminateProcess) },
			{ reinterpret_cast<void *>(RealExitProcess),      reinterpret_cast<void *>(&HookExitProcess) },
			{ kb != nullptr ? reinterpret_cast<void *>(GetProcAddress(kb, "TerminateProcess")) : nullptr, reinterpret_cast<void *>(&HookTerminateProcess) },
			{ kb != nullptr ? reinterpret_cast<void *>(GetProcAddress(kb, "ExitProcess")) : nullptr,      reinterpret_cast<void *>(&HookExitProcess) },
		};
		HMODULE mods[1024];
		DWORD needed = 0;
		if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return;
		HMODULE self = nullptr;
		GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(&Install), &self);
		for (DWORD i = 0; i < needed / sizeof(HMODULE) && i < 1024; ++i) {
			if (mods[i] == self || mods[i] == k32 || mods[i] == kb) continue;
			for (auto &t : targets) {
				if (t[0] != nullptr) PatchImports(mods[i], t[0], t[1]);
			}
		}
	}
}
#endif

bool CExtSigsegv::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
#if defined _WINDOWS
	/* A dedicated server has nobody to click an assertion dialog, which would
	 * hang it; report to stderr and abort instead, as glibc does. */
	_set_error_mode(_OUT_TO_STDERR);
	ExitTrace::Install();
#endif
#ifndef OPTIMIZE_MODS_ONLY
	ColorSpew::Enable();
#endif
	
	if (gameeventmanager != nullptr) {
		gameeventmanager->LoadEventsFromFile("resource/sigsegv_events.res");
	}
	
	this->LoadSoundOverrides();
	
	LibMgr::SetPtr(Library::SOURCEMODCORE,      menus);
	PreScan::DoScans();
	if (!g_GCHook.LoadAll(error, maxlength)) goto fail;
	
	LibMgr::Load();
//	g_Disasm.Load();
	
	RTTI::PreLoad();
	AddrManager::Load();
	
	g_pClientMode = reinterpret_cast<IClientMode *>(AddrManager::GetAddr("g_pClientMode"));
	
	if (!Link::InitAll()) goto fail;
	
	Prop::PreloadAll();
	
	g_pWorldEdict = engine->PEntityOfEntIndex(0);
	IExecMemManager::Load();
	g_ModManager.Load();
	
	IGameSystem::Add(this);

	ConVar_Restore::Load();
	ConVar_Restore::OnExtLoad();

	phrases = translator->CreatePhraseCollection();
	phrasesFile = phrases->AddPhraseFile("sigsegv.phrases");

	phrasesAttribs = translator->CreatePhraseCollection();
	phrasesAttribsFile = phrases->AddPhraseFile("sigsegvattributes.phrases");

	identity = sharesys->CreateIdentity(sharesys->CreateIdentType("Sigsegv"), this);
	
	laserSprite = CBaseEntity::PrecacheModel("materials/sprites/laser.vmt");
//	for (int i = 0; i < 255; ++i) {
//		ConColorMsg(Color(0xff, i, 0x00), "%02x%02x%02x\n", 0xff, i, 0x00);
//	}

	return true;
	
fail:
	g_GCHook.UnloadAll();
	return false;
}

void CExtSigsegv::SDK_OnUnload()
{
	ConVar_Restore::OnExtUnload();

	IGameSystem::Remove(this);
	
#ifdef SE_IS_TF2
	IHotplugActionBase::UnloadAll();
//	IHotplugEntity::UninstallAll();
#endif
	
	g_ModManager.Unload();
	CDetouredFunc::CleanUp();
	IExecMemManager::Unload();
	
	LibMgr::Unload();
	
	g_GCHook.UnloadAll();

#ifndef OPTIMIZE_MODS_ONLY
	ColorSpew::Disable();
#endif

	UnloadAllCustomThinkFunc();
	if (phrases != nullptr) {
		phrases->Destroy();
	}
}

void CExtSigsegv::SDK_OnAllLoaded()
{
}

bool CExtSigsegv::QueryRunning(char *error, size_t maxlength)
{
	return true;
}


#define GET_IFACE_OPTIONAL(factory, var, name) \
	var = reinterpret_cast<decltype(var)>(ismm->VInterfaceMatch(factory##Factory(), name, -1)); \
	if (var == nullptr) { \
		DevWarning("Could not find optional interface: %s\n", name); \
	}

#define GET_IFACE_REQUIRED(factory, var, name) \
	var = reinterpret_cast<decltype(var)>(ismm->VInterfaceMatch(factory##Factory(), name, -1)); \
	if (var == nullptr) { \
		if (error != nullptr && maxlength != 0) { \
			ismm->Format(error, maxlength, "Could not find required interface: %s", name); \
		} \
		return false; \
	}


bool CExtSigsegv::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlength, bool late)
{
	Msg("CExtSigsegv: compiled @ %s %s\n", GetBuildDate(), GetBuildTime());
	
	GET_IFACE_REQUIRED(Engine,     engine,            INTERFACEVERSION_VENGINESERVER);
#if SOURCE_ENGINE != SE_L4D
	GET_IFACE_REQUIRED(Server,     gamedll,           INTERFACEVERSION_SERVERGAMEDLL);
#else
	GET_IFACE_REQUIRED(Server,     gamedll,           "ServerGameDLL005");
#endif
	GET_IFACE_REQUIRED(FileSystem, filesystem,        FILESYSTEM_INTERFACE_VERSION);
	GET_IFACE_REQUIRED(Server,     serverGameClients, INTERFACEVERSION_SERVERGAMECLIENTS);
	GET_IFACE_REQUIRED(Server,     serverGameEnts,    INTERFACEVERSION_SERVERGAMEENTS);
	
	GET_IFACE_REQUIRED(Engine, icvar,              CVAR_INTERFACE_VERSION);
	GET_IFACE_REQUIRED(Engine, partition,          INTERFACEVERSION_SPATIALPARTITION);
	GET_IFACE_REQUIRED(Engine, enginetrace,        INTERFACEVERSION_ENGINETRACE_SERVER);
	GET_IFACE_REQUIRED(Engine, staticpropmgr,      INTERFACEVERSION_STATICPROPMGR_SERVER);
	GET_IFACE_REQUIRED(Engine, gameeventmanager,   INTERFACEVERSION_GAMEEVENTSMANAGER2);
	GET_IFACE_REQUIRED(Engine, networkstringtable, INTERFACENAME_NETWORKSTRINGTABLESERVER);
	GET_IFACE_REQUIRED(Engine, enginesound,        IENGINESOUND_SERVER_INTERFACE_VERSION);
	GET_IFACE_REQUIRED(Engine, modelinfo,          VMODELINFO_SERVER_INTERFACE_VERSION);
	
	GET_IFACE_REQUIRED(Server, playerinfomanager, INTERFACEVERSION_PLAYERINFOMANAGER);
	GET_IFACE_REQUIRED(Server, botmanager,        INTERFACEVERSION_PLAYERBOTMANAGER);
	GET_IFACE_REQUIRED(Server, servertools,       VSERVERTOOLS_INTERFACE_VERSION);
	GET_IFACE_REQUIRED(Server, g_pGameMovement,   INTERFACENAME_GAMEMOVEMENT);
	
	GET_IFACE_REQUIRED(VPhysics, physics,       VPHYSICS_INTERFACE_VERSION);
	GET_IFACE_REQUIRED(VPhysics, physcollision, VPHYSICS_COLLISION_INTERFACE_VERSION);
	GET_IFACE_REQUIRED(VPhysics, physprops,     VPHYSICS_SURFACEPROPS_INTERFACE_VERSION);
	
	GET_IFACE_OPTIONAL(Engine, debugoverlay, VDEBUG_OVERLAY_INTERFACE_VERSION);
	GET_IFACE_OPTIONAL(Engine, enginetools,  VENGINETOOL_INTERFACE_VERSION);

#ifdef VSCRIPT_INTERFACE_VERSION
	if (VScriptManagerFactory() != nullptr) {
		GET_IFACE_OPTIONAL(VScriptManager, scriptManager,  VSCRIPT_INTERFACE_VERSION);
	}
#endif
	
	if (SoundEmitterSystemFactory() != nullptr) {
		GET_IFACE_OPTIONAL(SoundEmitterSystem, soundemitterbase, SOUNDEMITTERSYSTEM_INTERFACE_VERSION);
	}
	
	if (MaterialSystemFactory() != nullptr) {
		GET_IFACE_OPTIONAL(MaterialSystem, g_pMaterialSystem, MATERIAL_SYSTEM_INTERFACE_VERSION);
	}
	if (VGUIFactory() != nullptr) {
		GET_IFACE_OPTIONAL(VGUI, g_pVGui,              VGUI_IVGUI_INTERFACE_VERSION);
		GET_IFACE_OPTIONAL(VGUI, g_pVGuiInput,         VGUI_INPUT_INTERFACE_VERSION);
		GET_IFACE_OPTIONAL(VGUI, g_pVGuiPanel,         VGUI_PANEL_INTERFACE_VERSION);
		GET_IFACE_OPTIONAL(VGUI, g_pVGuiSchemeManager, VGUI_SCHEME_INTERFACE_VERSION);
		GET_IFACE_OPTIONAL(VGUI, g_pVGuiSystem,        VGUI_SYSTEM_INTERFACE_VERSION);
		GET_IFACE_OPTIONAL(VGUI, g_pVGuiLocalize,      VGUI_LOCALIZE_INTERFACE_VERSION);
		GET_IFACE_OPTIONAL(VGUI, g_pVGuiInputInternal, VGUI_INPUTINTERNAL_INTERFACE_VERSION);
	}
	
	if (VGUIMatSurfaceFactory() != nullptr) {
		GET_IFACE_OPTIONAL(VGUIMatSurface, g_pVGuiSurface,      VGUI_SURFACE_INTERFACE_VERSION);
		GET_IFACE_OPTIONAL(VGUIMatSurface, g_pMatSystemSurface, MAT_SYSTEM_SURFACE_INTERFACE_VERSION);
	}
	
	if (ClientFactory() != nullptr) {
		GET_IFACE_REQUIRED(Engine, engineclient,  VENGINE_CLIENT_INTERFACE_VERSION);
		GET_IFACE_REQUIRED(Client, clientdll,     CLIENT_DLL_INTERFACE_VERSION);
		GET_IFACE_REQUIRED(Client, cl_entitylist, VCLIENTENTITYLIST_INTERFACE_VERSION);
		GET_IFACE_OPTIONAL(Client, clienttools,   VCLIENTTOOLS_INTERFACE_VERSION);
	}
	
	if (DedicatedFactory() != nullptr) {
		GET_IFACE_OPTIONAL(Dedicated, dedicated, VENGINE_DEDICATEDEXPORTS_API_VERSION);
	}
	
	if (DataCacheFactory() != nullptr) {
		GET_IFACE_OPTIONAL(DataCache, mdlcache, MDLCACHE_INTERFACE_VERSION);
	}
	
	GET_IFACE_REQUIRED(Engine, vprofexport, "VProfExport001");
	
	sv = engine->GetIServer();
	
	g_pCVar = icvar;
	ConVar_Register(0, this);
	
	gpGlobals     = ismm->GetCGlobals();
	gEntList      = servertools->GetEntityList();
	g_pEntityList = gEntList;
	
	LibMgr::SetPtr(Library::THIS,               this);
	LibMgr::SetPtr(Library::SERVER,             ServerFactory());
	LibMgr::SetPtr(Library::ENGINE,             EngineFactory());
	LibMgr::SetPtr(Library::DEDICATED,          DedicatedFactory());
	LibMgr::SetPtr(Library::TIER0,              &MemAllocScratch);
	LibMgr::SetPtr(Library::CLIENT,             ClientFactory());
	LibMgr::SetPtr(Library::VGUIMATSURFACE,     VGUIMatSurfaceFactory());
	LibMgr::SetPtr(Library::MATERIALSYSTEM,     MaterialSystemFactory());
	LibMgr::SetPtr(Library::SOUNDEMITTERSYSTEM, SoundEmitterSystemFactory());
	LibMgr::SetPtr(Library::DATACACHE,          DataCacheFactory());
	LibMgr::SetPtr(Library::VGUI,               VGUIFactory());
	LibMgr::SetPtr(Library::VPHYSICS,           VPhysicsFactory());
	LibMgr::SetPtr(Library::VSTDLIB,            icvar);
	LibMgr::SetPtr(Library::VSCRIPT,            VScriptManagerFactory());
	
	return true;
}

bool CExtSigsegv::SDK_OnMetamodUnload(char *error, size_t maxlength)
{
	return true;
}


bool CExtSigsegv::RegisterConCommandBase(ConCommandBase *pCommand)
{
	// Save only new commands
	if (icvar->FindVar(pCommand->GetName()) == nullptr) {
		ConVar_Restore::Register(pCommand);
	}
	
	META_REGCVAR(pCommand);
	return true;
}


void CExtSigsegv::LevelInitPreEntity()
{
	this->LoadSoundOverrides();
}

void CExtSigsegv::LevelInitPostEntity()
{
	g_pWorldEdict = engine->PEntityOfEntIndex(0);
	laserSprite = CBaseEntity::PrecacheModel("materials/sprites/laser.vmt");
}

void CExtSigsegv::LoadSoundOverrides()
{
	if (soundemitterbase != nullptr) {
		soundemitterbase->AddSoundOverrides("scripts/sigsegv_sound_overrides.txt", true);
	}
}

IdentityToken_t *CExtSigsegv::GetIdentity() const
{
	return identity;
}

//ConVar cvar_build("sig_build", __DATE__ " " __TIME__, FCVAR_NONE);
CON_COMMAND(sig_build, "")
{
	Msg("%s %s\n", GetBuildDate(), GetBuildTime());
}

#ifndef SE_L4D
CON_COMMAND(sig_cpu_usage, "")
{
	Msg("%f\n", GetCPUUsage());
}
#endif

CON_COMMAND(sig_memory_stats, "")
{
    char buffer[1024] = "";

    FILE* file = fopen("/proc/self/status", "r");

	while (fscanf(file, " %1023s", buffer) == 1) {

        if (strcmp(buffer, "VmRSS:") == 0) {
            fscanf(file, " %s", buffer);
			Msg("Current Real Memory: %s KB\n", buffer);
        }
        if (strcmp(buffer, "VmHWM:") == 0) {
            fscanf(file, " %s", buffer);
			Msg("Peak Real Memory: %s KB\n", buffer);
        }
        if (strcmp(buffer, "VmSize:") == 0) {
            fscanf(file, " %s", buffer);
			Msg("Current Virtual Memory: %s KB\n", buffer);
        }
        if (strcmp(buffer, "VmPeak:") == 0) {
            fscanf(file, " %s", buffer);
			Msg("Peak Virtual Memory: %s KB\n", buffer);
        }
    }
}