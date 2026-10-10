"""hexat.py RVA [LEN] [dll]: bytes at an RVA"""
import sys,pefile
dll=sys.argv[3] if len(sys.argv)>3 else "/home/mathis/b3/game-windows/tf/bin/server.dll"
pe=pefile.PE(dll,fast_load=True);img=pe.get_memory_mapped_image()
a=int(sys.argv[1],16);n=int(sys.argv[2],0) if len(sys.argv)>2 else 32
print(img[a:a+n].hex(' '))
