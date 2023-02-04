from struct import *
import sys,os,json

if(len(sys.argv)!=4):
    print("usage: python replay_updater.py record.dat old_record.json new_record.json")
    print(r"example: py .\replay_updater.py '.\2023.01.15 20.03.49.dat' ..\output\Global_2023.01.11\opcodes_record.json ..\output\Global_2023.01.17\opcodes_record.json")
    exit(0)
file = sys.argv[1]
oldop_file  = sys.argv[2]
newop_file  = sys.argv[3]
with open(oldop_file,'r') as f:
	old_dict=json.load(f)
with open(newop_file,'r') as f:
	new_dict=json.load(f)

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
if(old_dict['ver_id']!=replayVersion):
	print(f"opcodeVersion ({old_dict['ver_id']:08X}) not match replayVersion({replayVersion:08X})")
	exit(0)


fw=open(file.split(".dat")[0]+"_new.dat","wb+")

#0x0
fd.seek(0)
fw.seek(0)
#0x10
fw.write(fd.read(0x10))
#0x364
fw.write(pack('i', new_dict['ver_id']))
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

new=new_dict['opcodes']
old=old_dict['opcodes']
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