import sys,pefile,re
def load(dll):
    pe=pefile.PE(dll,fast_load=True);return bytes(pe.get_memory_mapped_image())
S="/home/mathis/b3/game-windows/tf/bin/server.dll"
E="/tmp/sigwin/game-windows/bin/engine.dll"
img={S:load(S),E:load(E)}
def chk(name,dll,addr,mn,mx,pat,eo,size):
    b=img[dll];toks=pat.split();n=len(toks)
    found=[]
    for off in range(mn,mx+1):
        ok=True
        for i,t in enumerate(toks):
            if t!='??' and b[addr+off+i]!=int(t,16): ok=False;break
        if ok: found.append(off)
    val=None
    if found: val=int.from_bytes(b[addr+found[0]+eo:addr+found[0]+eo+size],'little')
    print(f"{name:45} matches at {[hex(x) for x in found]} value {hex(val) if val is not None else None}")
chk('FireRocket',S,0x4cbb20,0,0x40,'8b f9 f3 0f 10 87 ?? ?? ?? ?? 0f 2f 40 0c',6,4)
chk('ArrowTouch',S,0x5f8b90,0,0x60,'f3 0f 10 40 0c 89 7d ?? f3 0f 5c 87 ?? ?? ?? ?? 0f 2f 05 ?? ?? ?? ??',12,4)
chk('SmackTime',S,0x63dc60,0,0x10,'8b f1 57 c7 86 ?? ?? ?? ?? 00 00 80 bf',5,4)
chk('VCollision',S,0x2e8ad0,0,0x10,'8b 45 10 56 8b f1 89 86 ?? ?? ?? ??',8,4)
chk('Clients',E,0x13f650,0,0x10,'8b d9 33 f6 57 33 ff 39 b3 ?? ?? ?? ?? 7e ?? 8b 83 ?? ?? ?? ??',17,4)
chk('Respec',S,0x5e4210,0,0x80,'8d 8e ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 0f b7 c0 3d ff ff 00 00',2,4)
chk('Sounds',S,0x635670,0,0x100,'8b 4d 08 5f 5e 85 c0 74 ?? 83 f9 0f 77 ?? 8b 84 88 ?? ?? ?? ??',17,4)
chk('Visuals',S,0x635670,0,0x100,'83 bc b0 ?? ?? ?? ?? 00 75 02 33 ff 8b 84 b8 ?? ?? ?? ??',15,4)
chk('EquipBit',S,0x3adcc0,0,0x2000,'33 ff 33 db c7 86 ?? ?? ?? ?? 00 00 00 00 57 68 ?? ?? ?? ?? c7 86 ?? ?? ?? ?? 00 00 00 00',6,4)
chk('EquipMask',S,0x3adcc0,0,0x2000,'33 ff 33 db c7 86 ?? ?? ?? ?? 00 00 00 00 57 68 ?? ?? ?? ?? c7 86 ?? ?? ?? ?? 00 00 00 00',22,4)
chk('NavCostVec',S,0x3dcbc0,0,0,'81 61 54 ff ff ff df c7 81 ?? ?? ?? ?? 00 00 00 00 c3',9,4)
chk('NavAttr',S,0x3dcbc0,0,0,'81 61 ?? ff ff ff df c7 81 ?? ?? ?? ?? 00 00 00 00 c3',2,1)
chk('NavCenter',S,0x3df390,0,0x60,'f3 0f 10 56 ?? 8d 45 f8 f3 0f 10 4e ?? 8d 4b 16 f3 0f 5c 4f ?? f3 0f 5c 57 ??',4,1)
chk('PVS',S,0x3e47a0,0,0x200,'8b b7 ?? ?? ?? ?? 33 c0 85 f6 7e 1a 8b 9f ?? ?? ?? ?? 8b cb',14,4)
chk('Incursion',S,0x575e90,0,0xa00,'83 f8 03 77 ?? 8b 4d 0c f3 0f 10 84 81 ?? ?? ?? ?? eb ?? f3 0f 10 05 ?? ?? ?? ??',13,4)
