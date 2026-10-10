"""winext.py FILE NAME TYPE 'hex with ??' FN MIN MAX EXTRACT_OFFSET [adjust-expression]
Replaces `using NAME = IExtractStub;` in FILE (under its _WINDOWS arm) with a byte-pattern extractor."""
import sys,re
file,name,typ,pat,fn,mn,mx,eo=sys.argv[1:9]
adj=sys.argv[9] if len(sys.argv)>9 else None
toks=pat.split()
buf=', '.join('0x00' if t=='??' else '0x'+t for t in toks)
masks=[]
i=0
while i<len(toks):
    if toks[i]=='??':
        j=i
        while j<len(toks) and toks[j]=='??': j+=1
        masks.append((i,j-i)); i=j
    else: i+=1
s=open(file,newline='').read()
nl='\r\n' if '\r\n' in s else '\n'
s=s.replace('\r\n','\n')
import re as _re
m_=_re.search(r'using '+name+r'\s*=\s*IExtractStub;',s)
assert m_ and len(_re.findall(r'using '+name+r'\s*=\s*IExtractStub;',s))==1,name
old=m_.group(0)
body=f'''static constexpr uint8_t s_Buf_{name}_Windows[] = {{
	{buf},
}};

struct {name} : public IExtract<{typ}>
{{
	using T = {typ};
	
	{name}() : IExtract<T>(sizeof(s_Buf_{name}_Windows)) {{}}
	
	virtual bool GetExtractInfo(ByteBuf& buf, ByteBuf& mask) const override
	{{
		buf.CopyFrom(s_Buf_{name}_Windows);
		
'''+''.join(f'\t\tmask.SetRange(0x{o:02x}, {n}, 0x00);\n' for o,n in masks)+f'''		
		return true;
	}}
	
	virtual const char *GetFuncName() const override   {{ return "{fn}"; }}
	virtual uint32_t GetFuncOffMin() const override    {{ return {mn}; }}
	virtual uint32_t GetFuncOffMax() const override    {{ return {mx}; }}
	virtual uint32_t GetExtractOffset() const override {{ return {eo}; }}
'''+(f'\tvirtual T AdjustValue(T val) const override        {{ return {adj}; }}\n' if adj else '')+'};'
s=s.replace(old,body)
open(file,'w',newline='').write(s.replace('\n',nl))
print('ok',name)
