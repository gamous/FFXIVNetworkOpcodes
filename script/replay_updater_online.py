import requests

from struct import *
import sys,os,json

if(len(sys.argv)<2):
    print("usage: python replay_updater.py record.dat")
    print(r"example: py .\replay_updater.py '.\2023.01.15 20.03.49.dat'")
    exit(0)
file = sys.argv[1]
target=''
search=None
if len(sys.argv)>=3:
    target = sys.argv[2]
if len(sys.argv)>4:
    search=sys.argv[4].encode('utf-8')

repo_url="https://raw.githubusercontent.com/gamous/FFXIVNetworkOpcodes/main/output/"
retry_times=5

RsvOpcde = 0xF001
RsfOpcde = 0xF002
DeltaOpCode = 0xF003

def safe_get(url):
    for i in range(retry_times):
        try:
            return requests.get(url)
        except requests.ConnectTimeout:
            print('Retry Download')
    exit(0)

meta=safe_get(repo_url+"meta.json").json()
if target=='':
    print("SupportVersion:")
    meta_l=list(meta)
    for i in meta_l:
        print(" "+i)
    default=meta_l[0]
    target=input(f"TargetVer(default{default}):").strip()
    if target=='':
        target=default
elif target=='latest':
    target=list(meta)[0]
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

source_file=safe_get(repo_url+f"{source}/opcodes_record.json").json()
target_file=safe_get(repo_url+f"{target}/opcodes_record.json").json()

newfile=file.split(".dat")[0]+f"_{target}.dat"
fw=open(newfile,"wb+")

#0x0
fd.seek(0)
fw.seek(0)
#0x10
fw.write(fd.read(0x10))
#0x30
fw.write(pack('i', meta[target]['ver_id']))
fd.read(calcsize("i"))
fw.write(fd.read(0x30-fd.tell()))
##0x364
fw.write(b'\0'*8)
fd.read(8)
fw.write(fd.read(0x364-fd.tell()))


count=[]
def parse_recordpacket(offset=0):
    if(offset):fd.seek(offset)
    opcode,dataLength,ms,objectID=unpack_filedatas('H H I I')

    #const opcode for rsv(0xf001),rsf(0xf002)
    if(opcode<0xf000):
        newopcode=newop(opcode)
    else:
        newopcode=opcode
    
    print(f"{opcode:x}=>{newopcode:x}|{dataLength:x}|{ms:x}|{objectID:x}")

    fw.write(pack('H H I I', newopcode,dataLength,ms,objectID))
    data=fd.read(dataLength)
    #print(type(opcode))
    
    #Privacy Protect
    if(opcode<0xf000):
        if(opcode2name[f"{opcode:03X}"]=='UpdateParty'):
            for i in range(8):
                data=data[0:0x1b8*i]+b'Player'.ljust(0x28,b'\0')+data[0x1b8*i+0x28:]
        elif(opcode2name[f"{opcode:03X}"]=='PlayerSpawn'):
            data=data[0:0x230]+b'Player'.ljust(0x20,b'\0')+data[0x230+0x20:]
        elif(opcode2name[f"{opcode:03X}"]=='CountdownInitiate'):
            data=data[0:0xb]+b'Player'.ljust(0x20,b'\0')+data[0xb+0x20:]
        
        #Delta Research
        elif(opcode2name[f"{opcode:03X}"]=='InitZone'):
            print(data)
            delta_key=data[0x15]
            delta_type=data[0x16]
            delta_time=unpack('I',data[0x18:0x1c])[0]
            data=data[0:0x15]+b'\0'+data[0x16:]
            print(f'Delta Parmas:  key={delta_key:x} type={delta_type:x} time={delta_time:x}')
            input()
    elif(opcode==0xF003):
        delta=unpack('I',data)[0]
        print(f'UpdateDelta:{delta:x}')
        input()
    if(search!=None and search in data):
        print(" ".join([f"{i:02x}"for i in data]))
        count.append(opcode)

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
print(list(map(lambda op:opcode2name[f"{op:03X}"],set(count))))
fd.close()
fw.close()
print('Saved on '+newfile)