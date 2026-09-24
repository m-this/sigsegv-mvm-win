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
/* Who ends the server. The engine's Error() leaves through tier0's
 * Plat_ExitProcess, TerminateProcess on itself with status 100, and on
 * Windows its message never reaches console.log: a server that died that way
 * looked like one that simply stopped. Every loaded module's imports of
 * TerminateProcess and ExitProcess are pointed here, which writes the calling
 * stack as module+offset to sigsegv_exit.txt in the game directory and to the
 * console, then does what was asked. */
namespace ExitTrace
{
	using TerminateProcess_t = BOOL (WINAPI *)(HANDLE, UINT);
	using ExitProcess_t      = void (WINAPI *)(UINT);
	TerminateProcess_t RealTerminateProcess = nullptr;
	ExitProcess_t      RealExitProcess      = nullptr;
	
	void Write(const char *what, UINT code)
	{
		void *frames[48];
		USHORT n = RtlCaptureStackBackTrace(1, 48, frames, nullptr);
		FILE *f = fopen("sigsegv_exit.txt", "a");
		char line[512];
		snprintf(line, sizeof(line), "SigMod: %s(%u) called from:\n", what, code);
		if (f != nullptr) fputs(line, f);
		Warning("%s", line);
		for (USHORT i = 0; i < n; ++i) {
			HMODULE mod = nullptr;
			char path[MAX_PATH] = "?";
			if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCSTR>(frames[i]), &mod) && mod != nullptr) {
				GetModuleFileNameA(mod, path, sizeof(path));
			}
			const char *base = strrchr(path, '\\');
			snprintf(line, sizeof(line), "  %s+0x%x\n", base != nullptr ? base + 1 : path,
				mod != nullptr ? (unsigned)((uintptr_t)frames[i] - (uintptr_t)mod) : (unsigned)(uintptr_t)frames[i]);
			if (f != nullptr) fputs(line, f);
			Warning("%s", line);
		}
		if (f != nullptr) fclose(f);
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
	
	void Install()
	{
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