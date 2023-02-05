import idaapi
import idc
import idautils
import ida_bytes
import ida_nalt
import ida_search
import ida_ua
import os
import json
import functools
import re

ConfigPath = os.path.dirname(os.path.realpath(__file__))
OutputPath = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    f"output",
)
print("Begin FFXIVRecordFinder...")
slist = idautils.Strings()
slist_s = [str(s) for s in slist]  # s.ea, s.length, s.type, str(s)
for s in slist_s:
    if r"/*****ff14******rev" in s:
        BuildID = s[27:37].replace('/', '.')
        VersionID = int(s[19:26])
        break
for s in slist_s:
    if r"ffxiv_dx11.pdb" in s:
        Region_s,version_s=s.split('\\')[4].split('_')
        break
if Region_s == 'shanda':
    Region='CN'
elif Region_s == 'ver':
    Region='Global'
else:
    Region='Unknown'
print(f"{Region} {version_s} {VersionID:08X} {BuildID}")

output_dir = os.path.join(
    OutputPath,
    f"{Region}_{BuildID}",
)
if not os.path.exists(output_dir):
    os.makedirs(output_dir)
outpath = lambda name: os.path.join(
    output_dir,
    name,
)

opcodes_internal_path = outpath("opcodes_internal.json")
if not os.path.exists(opcodes_internal_path):
    print("Please run ffxiv_opcodes_finder.py first.")
    exit(0)
print(opcodes_internal_path)
with open(opcodes_internal_path, "r") as f:
    opcodes_internal=json.load(f)
_opcode2name={f"{opcodes_internal['lists']['ServerZoneIpcType'][k]:03X}":k for k in opcodes_internal["lists"]["ServerZoneIpcType"]}
def opcode2name(opcode):
    if opcode in _opcode2name:
        return _opcode2name[opcode]
    return "unk"
#c:\\ws\\ver_630_winbuild\\branches\\ver_630\\trunk\\prog\\client\\Build\\FFXIVGame\\x64-Release\\ffxiv_dx11.pdb
#c:\\ws\\shanda_620_winbuild\\branches\\shanda_620\\trunk\\prog\\client\\Build\\FFXIVGame\\x64-Release\\ffxiv_dx11.pdb

def find_pattern(pattern):
    address = ida_search.find_binary(ida_ida.cvar.inf.omin_ea, ida_ida.cvar.inf.omax_ea, pattern, 16, ida_search.SEARCH_DOWN)
    return address

def find_function(pattern):
    addr=find_pattern(pattern)
    if idc.print_insn_mnem(addr)=='call':
        addr=idc.get_wide_word(addr+1) + idc.next_head(addr)
    return addr

def set_type(ea, type_str):
    _type = idc.parse_decl(type_str, 0)  
    idc.apply_type(ea, _type, 0)

record_packet = find_function("E8 ? ? ? ? 84 C0 74 60 33 C0")
set_type(record_packet,"char __fastcall Replay_RecordPacket(__int64 this, unsigned int targetid, unsigned short opcode, const void *packet, size_t size)")
packets=CodeRefsTo(record_packet,0)
opcode={}

i=0
for pkt in packets:
    print('%x' % pkt)
    pkt_opcode='0'
    pkt_size='0'
    
    for arg in idaapi.get_arg_addrs(pkt):
        if arg==0xffffffffffffffff:
            continue
        op0=idc.print_operand(arg, 0)
        op1=idc.print_operand(arg, 1)
        # print('%x' % arg)
        if op0 == 'r8d':
            pkt_opcode=op1
        if op0.startswith('[rsp+'):
            pkt_size=op1
    pkt_opcode=pkt_opcode.rstrip("h").lstrip("0").rjust(3,'0')
    pkt_size  =pkt_size.rstrip("h").lstrip("0").rjust(3,'0')
    opcode[f'{i}']=[f"{pkt:x}",pkt_opcode,pkt_size,opcode2name(pkt_opcode)]
    i+=1

size_seq=[opcode[k][2] for k in opcode]
result={
    "version": BuildID,
    "region": Region,
    "ver_id":VersionID,
    "opcodes":opcode,
    "lengths":size_seq
}
print(json.dumps(result))

class MyJSONEncoder(json.JSONEncoder):
  def iterencode(self, o, _one_shot=False):
    list_lvl = 0
    for s in super(MyJSONEncoder, self).iterencode(o, _one_shot=_one_shot):
      if s.startswith('['):
        list_lvl += 1
        s = s.replace('\n', '').rstrip()
      elif 0 < list_lvl:
        s = s.replace('\n', '').rstrip()
        if s and s[-1] == ',':
          s = s[:-1] + self.item_separator
        elif s and s[-1] == ':':
          s = s[:-1] + self.key_separator
      if s.endswith(']'):
        list_lvl -= 1
      yield s

result_path = outpath("opcodes_record_raw.json")
with open(result_path, "w+") as f:
    json.dump(result, f, sort_keys=False, indent=2, separators=(',', ':'), cls=MyJSONEncoder)
    print(f"Result saved on {result_path}")



