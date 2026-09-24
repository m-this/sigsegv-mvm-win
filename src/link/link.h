#ifndef _INCLUDE_SIGSEGV_LINK_LINK_H_
#define _INCLUDE_SIGSEGV_LINK_LINK_H_


#include "util/autolist.h"
#include "addr/addr.h"
#include "util/rtti.h"


#if defined _WINDOWS
/* A call through a thunk the Windows address table has no entry for. It ends
 * the server with the function's name, unless SIGSEGV_SURVEY_UNRESOLVED is set
 * in the environment: then it names the function once and the call returns
 * zero, so one bed sweep lists every missing function the missions reach
 * rather than the first. The survey is for the bed; a player never sets it. */
void UnresolvedCall(const char *what, const char *name);

template<typename R>
inline R UnresolvedValue()
{
	if constexpr (std::is_void_v<R>) {
		return;
	} else if constexpr (std::is_reference_v<R>) {
		static auto *zero = static_cast<std::remove_reference_t<R> *>(calloc(1, sizeof(std::remove_reference_t<R>)));
		return *zero;
	} else {
		alignas(R) static const unsigned char zero[sizeof(R)] = {};
		return *reinterpret_cast<const R *>(zero);
	}
}
#endif


class ILinkage : public AutoListNoDelete<ILinkage>
{
public:
	//virtual ~ILinkage() {}
	
	void InvokeLink()
	{
		if (this->m_bLinked) return;
		
		this->m_bLinked = this->Link();
	}
	
	void ForceLink(uintptr_t addr)
	{
		this->ForceAddr(addr);
		this->m_bLinked = true;
	}
	
	bool IsLinked() const { return this->m_bLinked; }
	virtual bool ClientSide() { return false; }

	virtual const char *GetNameDebug() { return nullptr; }
	virtual const char *GetTypeDebug() { return nullptr; }
	virtual uintptr_t GetAddressDebug() { return 0; }
	
protected:
	ILinkage() {}
	
	virtual bool Link() = 0;
	virtual void ForceAddr(uintptr_t addr) = 0;
	
private:
	bool m_bLinked = false;
};


class StaticFuncThunkBase : public ILinkage
{
public:
	StaticFuncThunkBase(const char *n_func) :
		m_pszFuncName(n_func) {}

	virtual bool Link() override
	{
		if (this->m_pFuncPtr == nullptr) {
			this->m_pFuncPtr = AddrManager::GetAddr(this->m_pszFuncName);
			if (this->m_pFuncPtr == nullptr) {
				Warning("StaticFuncThunk::Link FAIL \"%s\": can't find func addr\n", this->m_pszFuncName);
				return false;
			}
		}
		
		return true;
	}

	virtual const char *GetNameDebug() { return m_pszFuncName; }
	const char *GetFuncName() const { return m_pszFuncName; }
	virtual const char *GetTypeDebug() { return "STATIC_FUNC"; }
	virtual uintptr_t GetAddressDebug() { return (uintptr_t) m_pFuncPtr; }
	const void *GetFuncPtr() const { return this->m_pFuncPtr; }

private:
	virtual void ForceAddr(uintptr_t addr) override { this->m_pFuncPtr = (const void *)addr; }
	
	
	const char *m_pszFuncName;
	
	const void *m_pFuncPtr = nullptr;

	virtual bool ClientSide() override { return strnicmp(this->m_pszFuncName, "[client]", strlen("[client]")) == 0; }
};

template<typename RET, typename... PARAMS>
class StaticFuncThunk
{
public:
	using RetType = RET;
	using FPtr = RET (*)(PARAMS...);
	
	StaticFuncThunk(const char *n_func) : link(n_func) {}
	
	inline RET operator()(PARAMS... args) const
	{
#if defined _WINDOWS
		/* the Windows address table is incomplete; name the gap instead of jumping to 0 */
		if (link.GetFuncPtr() == nullptr) { UnresolvedCall("called unresolved function", link.GetFuncName()); return UnresolvedValue<RET>(); }
#endif
#ifdef DEBUG
		assert(link.GetFuncPtr() != nullptr); 
#endif
		return (*(FPtr)link.GetFuncPtr())(args...);
	}
	bool IsLinked() const { return link.IsLinked(); }
private:
	StaticFuncThunkBase link;
};

//template<class C, typename RET, typename... PARAMS>
class MemberFuncThunkBase : public ILinkage
{
public:
	//using RetType = RET;
	
	MemberFuncThunkBase(const char *n_func) :
		m_pszFuncName(n_func) {}
	
	virtual bool Link() override
	{
		if (this->m_pFuncPtr == nullptr) {
			this->m_pFuncPtr = AddrManager::GetAddr(this->m_pszFuncName);
			if (this->m_pFuncPtr == nullptr) {
				Warning("MemberFuncThunk::Link FAIL \"%s\": can't find func addr\n", this->m_pszFuncName);
				return false;
			}
		}
		
//		DevMsg("MemberFuncThunk::Link OK 0x%08x \"%s\"\n", (uintptr_t)this->m_pFuncPtr, this->m_pszFuncName);
		return true;
	}
	
	virtual const char *GetNameDebug() { return m_pszFuncName; }
	const char *GetFuncName() const { return m_pszFuncName; }
	virtual const char *GetTypeDebug() { return "MEMBER_FUNC"; }
	virtual uintptr_t GetAddressDebug() { return (uintptr_t)m_pFuncPtr; }
	const void *GetFuncPtr() const { return this->m_pFuncPtr; }
	
private:
	virtual void ForceAddr(uintptr_t addr) override { this->m_pFuncPtr = (const void *)addr; }
	
	const char *m_pszFuncName;
	
	const void *m_pFuncPtr = nullptr;

	virtual bool ClientSide() override { return strnicmp(this->m_pszFuncName, "[client]", strlen("[client]")) == 0; }
};

template<class C, typename RET, typename... PARAMS>
class MemberFuncThunk//<C, RET, PARAMS...>
{
public:
	MemberFuncThunk(const char *n_func) :
		link/*<C, RET, PARAMS...>*/(n_func) {}
private:
	MemberFuncThunkBase link;
};

template<class C, typename RET, typename... PARAMS>
class MemberFuncThunk<C *, RET, PARAMS...> //<C, RET, PARAMS...>
{
public:

// For gcc thiscall callconv, `this` is essentally the first argument of a function, so call the function like a static, this way 'fat' function pointers can be avoided
#ifdef __GNUC__
	using FPtr = RET (*)(C*, PARAMS...);
#else
	using FPtr = RET (C::*)(PARAMS...);
#endif
	
	MemberFuncThunk(const char *n_func) :
		link(n_func) {}
	
	inline RET operator()(const C *obj, PARAMS... args) const = delete;
	inline RET operator()(      C *obj, PARAMS... args) const
	{
#if defined _WINDOWS
		/* the Windows address table is incomplete; name the gap instead of jumping to 0 */
		if (link.GetFuncPtr() == nullptr) { UnresolvedCall("called unresolved function", link.GetFuncName()); return UnresolvedValue<RET>(); }
#endif
#ifdef __GNUC__
		FPtr pFunc= (FPtr)link.GetFuncPtr();
#else
		FPtr pFunc = MakePtrToMemberFunc<C, RET, PARAMS...>(link.GetFuncPtr());
#endif

#ifdef DEBUG
		assert(pFunc != nullptr);
		assert(obj   != nullptr);
#endif

#ifdef __GNUC__
		return (*pFunc)(obj, args...);
#else
		return (obj->*pFunc)(args...);
#endif
	}
private:
	MemberFuncThunkBase link;
};

template<class C, typename RET, typename... PARAMS>
class MemberFuncThunk<const C *, RET, PARAMS...>//<C, RET, PARAMS...>
{
public:

// Slightly shrink stuff
#ifdef __GNUC__
	using FPtr = RET (*)(const C*, PARAMS...);
#else
	using FPtr = RET (C::*)(PARAMS...) const;
#endif
	
	MemberFuncThunk(const char *n_func) :
		link/*<C, RET, PARAMS...>*/(n_func) {}
	
	inline RET operator()(      C *obj, PARAMS... args) const = delete;
	inline RET operator()(const C *obj, PARAMS... args) const
	{
#if defined _WINDOWS
		/* the Windows address table is incomplete; name the gap instead of jumping to 0 */
		if (link.GetFuncPtr() == nullptr) { UnresolvedCall("called unresolved function", link.GetFuncName()); return UnresolvedValue<RET>(); }
#endif
#ifdef __GNUC__
		FPtr pFunc= (FPtr)link.GetFuncPtr();
#else
		FPtr pFunc = MakePtrToConstMemberFunc<C, RET, PARAMS...>(link.GetFuncPtr());
#endif

#ifdef DEBUG
			assert(pFunc != nullptr);
			assert(obj   != nullptr);
#endif
		
#ifdef __GNUC__
		return (*pFunc)(obj, args...);
#else
		return (obj->*pFunc)(args...);
#endif
	}
private:
	MemberFuncThunkBase link;
};


class MemberVFuncThunkBase : public ILinkage
{
public:
	MemberVFuncThunkBase(const char *n_vtable, const char *n_func, int entry_num = 0) :
		m_pszVTableName(n_vtable), m_pszFuncName(n_func), m_iEntryNumber(entry_num) {}
	
	virtual bool Link() override
	{
		const void **pVT  = nullptr;
		const void *pFunc = nullptr;
		
		if (this->m_iVTIndex == -1) {
			pVT = RTTI::GetVTable(this->m_pszVTableName);
			if (pVT == nullptr) {
				Warning("MemberVFuncThunk::Link FAIL \"%s\": can't find vtable\n", this->m_pszFuncName);
				return false;
			}
			
			pFunc = AddrManager::GetAddr(this->m_pszFuncName);
			if (pFunc == nullptr) {
				Warning("MemberVFuncThunk::Link FAIL \"%s\": can't find func addr\n", this->m_pszFuncName);
				return false;
			}
			
			bool found = false;
			int num = 0;
			for (int i = 0; i < 0x1000; ++i) {
				if (pVT[i] == pFunc) {
					if(num++ >= m_iEntryNumber) {
						this->m_iVTIndex = i;
						found = true;
						break;
					}
				}
			}
			
			if (!found) {
				Warning("MemberVFuncThunk::Link FAIL \"%s\": can't find func ptr in vtable\n", this->m_pszFuncName);
				return false;
			}
		}
		
//		DevMsg("MemberVFuncThunk::Link OK +0x%x \"%s\"\n", this->m_iVTIndex * 4, this->m_pszFuncName);
		return true;
	}

	virtual const char *GetNameDebug() { return m_pszFuncName; }
	virtual const char *GetTypeDebug() { return "VIRTUAL_FUNC"; }
	virtual uintptr_t GetAddressDebug() { return GetVTableIndex() * sizeof(uintptr_t); }
	int GetVTableIndex() const { return this->m_iVTIndex; }
	const char *GetFuncName() const { return this->m_pszFuncName; }
	
private:
	virtual void ForceAddr(uintptr_t addr) override { this->m_iVTIndex = addr; }
	
	const char *m_pszVTableName;
	const char *m_pszFuncName;
	
	int m_iVTIndex = -1;

	int m_iEntryNumber = 0;

	virtual bool ClientSide() override { return strnicmp(this->m_pszFuncName, "[client]", strlen("[client]")) == 0; }
};

template<class C, typename RET, typename... PARAMS>
class MemberVFuncThunk
{
public:
	using RetType = RET;
	
	MemberVFuncThunk(const char *n_vtable, const char *n_func) :
		link(n_vtable, n_func) {}
private:
	MemberVFuncThunkBase link;
};

template<class C, typename RET, typename... PARAMS>
class MemberVFuncThunk<C *, RET, PARAMS...>
{
public:
	using RetType = RET;
#ifdef __GNUC__
	using FPtr = RET (*)(C*, PARAMS...);
#else
	using FPtr = RET (C::*)(PARAMS...);
#endif
	
	MemberVFuncThunk(const char *n_vtable, const char *n_func) :
		link(n_vtable, n_func) {}
	
	inline RET operator()(const C *obj, PARAMS... args) const = delete;
	inline RET operator()(      C *obj, PARAMS... args) const
	{
		int vt_index = link.GetVTableIndex();
		
#ifdef DEBUG
		assert(vt_index != -1);
		assert(obj != nullptr);
#endif
#if defined _WINDOWS
		/* an index of -1 would read the slot before the vtable and call whatever
		   is there; the Windows address table is still incomplete */
		if (vt_index == -1) { UnresolvedCall("virtual function with no vtable index", link.GetFuncName()); return UnresolvedValue<RET>(); }
#endif
		
		auto pVT = *reinterpret_cast<void **const *>(obj);
#ifdef __GNUC__
		return (*(FPtr)pVT[vt_index])(obj, args...);
#else
		FPtr pFunc = MakePtrToMemberFunc<C, RET, PARAMS...>(pVT[vt_index]);
		return (obj->*pFunc)(args...);
#endif
	}
private:
	MemberVFuncThunkBase link;
};

template<class C, typename RET, typename... PARAMS>
class MemberVFuncThunk<const C *, RET, PARAMS...>
{
public:
	using RetType = RET;
#ifdef __GNUC__
	using FPtr = RET (*)(const C*, PARAMS...);
#else
	using FPtr = RET (C::*)(PARAMS...) const;
#endif
	
	MemberVFuncThunk(const char *n_vtable, const char *n_func) :
		link(n_vtable, n_func) {}
	
	inline RET operator()(      C *obj, PARAMS... args) const = delete;
	inline RET operator()(const C *obj, PARAMS... args) const
	{
		int vt_index = link.GetVTableIndex();
		
#ifdef DEBUG
		assert(vt_index != -1);
		assert(obj != nullptr);
#endif
#if defined _WINDOWS
		/* an index of -1 would read the slot before the vtable and call whatever
		   is there; the Windows address table is still incomplete */
		if (vt_index == -1) { UnresolvedCall("virtual function with no vtable index", link.GetFuncName()); return UnresolvedValue<RET>(); }
#endif
		
		auto pVT = *reinterpret_cast<void **const *>(obj);
		
#ifdef __GNUC__
		return (*(FPtr)pVT[vt_index])(obj, args...);
#else
		FPtr pFunc = MakePtrToConstMemberFunc<C, RET, PARAMS...>(pVT[vt_index]);
		return (obj->*pFunc)(args...);
#endif
	}
private:
	MemberVFuncThunkBase link;
};


class GlobalThunkBase : public ILinkage
{
public:
	GlobalThunkBase(const char *n_obj) :
		m_pszObjName(n_obj) {}
	
	virtual bool Link() override
	{
		if (this->m_pObjPtr == nullptr) {
			this->m_pObjPtr = AddrManager::GetAddr(this->m_pszObjName);
			if (this->m_pObjPtr == nullptr) {
				Warning("GlobalThunk::Link FAIL \"%s\": can't find global addr\n", this->m_pszObjName);
				return false;
			}
		}
		
//		DevMsg("GlobalThunk::Link OK 0x%08x \"%s\"\n", (uintptr_t)this->m_pObjPtr, this->m_pszObjName);
		return true;
	}
	
	virtual const char *GetNameDebug() { return m_pszObjName; }
	virtual const char *GetTypeDebug() { return "GLOBAL"; }
	const char *GetObjName() const { return m_pszObjName; }
	virtual uintptr_t GetAddressDebug() { return  (uintptr_t) this->m_pObjPtr; }
	void *m_pObjPtr = nullptr;

private:
	virtual void ForceAddr(uintptr_t addr) override { this->m_pObjPtr = (void *)addr; }
	
	const char *m_pszObjName;
	

	virtual bool ClientSide() override { return strnicmp(this->m_pszObjName, "[client]", strlen("[client]")) == 0; }
};

template<typename T>
class GlobalThunk
{
public:
	GlobalThunk(const char *n_obj) : link(n_obj) {}
	
	inline operator T&() const
	{
		
#ifdef DEBUG
		assert(this->m_pObjPtr != nullptr);
#endif
		return this->GetRef();
	}
	
	inline T& operator->() const
	{
		return this->GetRef();
	}
	
	inline T& GetRef() const
	{
		/* An array of unknown bound or a function has no size to zero. */
		if constexpr (!std::is_function_v<T> && !std::is_unbounded_array_v<T>) {
			if (link.m_pObjPtr == nullptr) {
				return this->Unresolved();
			}
		}
		return *(T *)link.m_pObjPtr;
	}
	inline bool IsLinked() const { return link.m_pObjPtr != nullptr; }
	
protected:
	inline T *GetPtr() const { return std::addressof(this->GetRef()); }
private:
	/* A global the gamedata could not find, which on Windows is dozens.
	 * Reading one dereferenced null and killed the server as soon as a mod
	 * touched it, at load for any mod the convar file enables. It reads as
	 * zero bytes of its own now, so a pointer global reads null and the
	 * caller's null check runs. */
	T& Unresolved() const
	{
		if (this->m_pUnresolved == nullptr) {
			this->m_pUnresolved = static_cast<T *>(calloc(1, sizeof(T)));
			Warning("GlobalThunk: \"%s\" is unresolved and reads as zero\n", link.GetObjName());
		}
		return *this->m_pUnresolved;
	}
	
	GlobalThunkBase link;
	mutable T *m_pUnresolved = nullptr;
};

template<typename T>
class GlobalThunkRW : public GlobalThunk<T>
{
public:
	GlobalThunkRW(const char *n_obj) :
		GlobalThunk<T>(n_obj) {}
	
	inline T& operator=(T& that)
	{
		*this->GetPtr() = that;
		return that;
	}
};


template<size_t SIZE>
class TypeInfoThunk : public ILinkage
{
public:
	TypeInfoThunk(const char *name, uint8_t *dst) :
		m_pszName(name), m_pDest(dst) {}
	
	virtual bool Link() override
	{
		auto rtti = RTTI::GetRTTI(this->m_pszName);
		if (rtti == nullptr) {
			static_assert((SIZE % sizeof(intptr_t)) == 0);
			std::fill_n((intptr_t *)m_pDest, SIZE / sizeof(intptr_t), 0xABAD1DEA);
			
			Warning("TypeInfoThunk::Link FAIL \"%s\": can't find RTTI\n", this->m_pszName);
			return false;
		}
		
		memcpy(m_pDest, rtti, SIZE);
		
		DevMsg("TypeInfoThunk::Link OK \"%s\"\n", this->m_pszName);
		return true;
	}
	
private:
	virtual void ForceAddr(uintptr_t addr) override { /* unimplemented */ }
	
	const char *m_pszName;
	uint8_t *m_pDest;
};


template<size_t SIZE>
class VTableThunk : public ILinkage
{
public:
	VTableThunk(const char *name, uint8_t *dst) :
		m_pszName(name), m_pDest(dst) {}
	
	virtual bool Link() override
	{
		auto vt = RTTI::GetVTable(this->m_pszName);
		if (vt == nullptr) {
			static_assert((SIZE % sizeof(intptr_t)) == 0);
			std::fill_n((intptr_t *)m_pDest, SIZE / sizeof(intptr_t), 0xABAD1DEA);
			
			Warning("VTableThunk::Link FAIL \"%s\": can't find vtable\n", this->m_pszName);
			return false;
		}
		
#if defined _MSC_VER
		ptrdiff_t adj = 0;
#else
		ptrdiff_t adj = -offsetof(vtable, vfptrs);
#endif
		
		memcpy(m_pDest, (void *)((uintptr_t)vt + adj), SIZE);
		
		DevMsg("VTableThunk::Link OK \"%s\"\n", this->m_pszName);
		return true;
	}
	
private:
	virtual void ForceAddr(uintptr_t addr) override { /* unimplemented */ }
	
	const char *m_pszName;
	uint8_t *m_pDest;
};


/* for those times when you want to call a vfunc in the base class, not through
 * the vtable */
template<class C, typename RET, typename... PARAMS>
RET CallNonVirt(C *obj, const char *n_func, PARAMS... args)
{
	assert(obj != nullptr);
	
	void *addr = AddrManager::GetAddr(n_func);
	assert(addr != nullptr);
	
	auto pFunc = MakePtrToMemberFunc<C, RET, PARAMS...>(addr);
	return (obj->*pFunc)(args...);
}


/* easy way to leverage existing code to find a VT entry offset */
class VTOffFinder : public MemberVFuncThunkBase
{
public:
	VTOffFinder(const char *n_vtable, const char *n_func, int entry_num = 0) :
		MemberVFuncThunkBase(n_vtable, n_func, entry_num)
	{
		this->InvokeLink();
	}
	
	bool IsValid() const       { return (this->GetVTableIndex() != -1); }
	operator ptrdiff_t() const { return (this->GetVTableIndex() * sizeof(ptrdiff_t)); }
};


#endif
