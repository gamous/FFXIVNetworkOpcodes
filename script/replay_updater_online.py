import httpx

from struct import *
import sys,os,json

if(len(sys.argv)!=2 and len(sys.argv)!=3):
    print("usage: python replay_updater.py record.dat")
    print(r"example: py .\replay_updater.py '.\2023.01.15 20.03.49.dat'")
    exit(0)
file = sys.argv[1]
target=''
if len(sys.argv)==3:
    target = sys.argv[2]

repo_url="https://raw.githubusercontent.com/gamous/FFXIVNetworkOpcodes/main/output/"
meta=httpx.get(repo_url+"meta.json").json()
if target=='':
    default=list(meta)[0]
    target=input(f"TargetVer(default{default}):").strip()
    if target=='':
        target=default
if(target not in meta):
    print('Target Not Found')
    exit(0)

fd=open(file,"rb")
magicNumber = fd.read(12)
if(magicNumber!=b'FFXIVREPLAY\x00'):
    print("Is not FFXIVREPLAY file")
    exit(0)

def unpack_filedata(typechar,offset=0):
    if(offset):fd.seek(offset)
    raw = fd.read(calcsize(typechar))
    return unpack(typechar, raw)[0]

def unpack_filedatas(typechar,offset=0):
    if(offset):fd.seek(offset)
    raw = fd.read(calcsize(typechar))
    return unpack(typechar, raw)

fd.seek(0)
replayVersion=unpack_filedata('i', 0x10)
replayLength=unpack_filedata('i', 0x48)
print(f"replayVersion: 0x{replayVersion:08X}")
print(f"replayLength:  0x{replayLength:08X}({replayLength})")
replayLength+=0x364

source=''
for k in meta:
    if meta[k]['ver_id']==replayVersion:
        source=k
        print(f"Found Version: {source}")
        break
if source =='':
    print("Not Found replayVersion")
    exit(0)

source_file=httpx.get(repo_url+f"{source}/opcodes_record.json").json()
target_file=httpx.get(repo_url+f"{target}/opcodes_record.json").json()

fw=open(file.split(".dat")[0]+"_new.dat","wb+")

#0x0
fd.seek(0)
fw.seek(0)
#0x10
fw.write(fd.read(0x10))
#0x364
fw.write(pack('i', target_file['ver_id']))
fw.write(fd.read(0x364-fd.tell()))

def parse_recordpacket(offset=0):
    if(offset):fd.seek(offset)
    opcode,dataLength,ms,objectID=unpack_filedatas('H H I I')
    
    newopcode=newop(opcode)
    print(f"{opcode:x}=>{newopcode:x}|{dataLength:x}|{ms:x}|{objectID:x}")

    fw.write(pack('H H I I', newopcode,dataLength,ms,objectID))
    data=fd.read(dataLength)
    #print(" ".join([f"{i:02x}"for i in data]))
    fw.write(data)


new=target_file['opcodes']
old=source_file['opcodes']
def _opcode2name(l):
    return {l[k][1]:l[k][3] for k in l}
def _name2opcode(l):
    return {l[k][3]:l[k][1] for k in l}
name2opcode=_name2opcode(new)
opcode2name=_opcode2name(old)
newop = lambda op: int(name2opcode[opcode2name[f"{op:03X}"]],16)

while(fd.tell()<replayLength):
	parse_recordpacket()

fd.close()
fw.close()