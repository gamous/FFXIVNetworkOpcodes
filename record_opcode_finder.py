import idaapi
import idc
import idautils
import ida_bytes
import ida_nalt
import ida_xref
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
#c:\\ws\\ver_630_winbuild   \\branches\\ver_630   \\trunk\\prog\\client\\Build\\FFXIVGame\\x64-Release\\ffxiv_dx11.pdb
#c:\\ws\\shanda_620_winbuild\\branches\\shanda_620\\trunk\\prog\\client\\Build\\FFXIVGame\\x64-Release\\ffxiv_dx11.pdb
#########
# Utils #
#########
min_ea = idaapi.inf_get_min_ea()
max_ea = idaapi.inf_get_max_ea()
JMP_INS = ["jmp", "jz", "ja", "jb", "jnz"]
CALL_INS = ["call"]
RET_INS = ["ret", "retn"]
CTRL_INS = JMP_INS + CALL_INS + RET_INS


def get_ctrl_target(ea):
    xrefs = list(idautils.XrefsFrom(ea, flags=1))
    return xrefs[0].to if len(xrefs) > 0 else idc.BADADDR

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

class SimpleSwitch:
    def __init__(self, switch_address) -> None:
        self.content = []
        self.switch_func = idaapi.get_func(switch_address)
        self.switch_func_item = list(idautils.FuncItems(switch_address))
        self.process_case_block(self.switch_func.start_ea, 0, 0, False,'')
        print(self.content)

    def process_case_block(self, start, rcase, ccase, iscmp, reg):
        _reg=reg #r10d
        _reg_case = rcase
        _t_mov_op1 = 0
        _t_cmp_tmp = ccase
        _t_cmp_yes = iscmp
        
        for ea in self.switch_func_item:
            if ea < start:
                continue
            ins = idc.print_insn_mnem(ea)
            op0 = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            if ins in JMP_INS:
                self.process_case_block(
                    get_ctrl_target(ea), _reg_case, _t_cmp_tmp, _t_cmp_yes, _reg
                )
                continue
            if ins in RET_INS:
                continue
            if ins == "mov":
                #print(f'[mov]{ea:x}')
                _t_mov_op1 = int(op1.strip('h'), 16)
                continue
            if ins == "movzx" and op1=='r8w':
                _reg=op0
                print(_reg)
                continue
            if ins == "call":
                _case = _t_cmp_tmp if _t_cmp_yes else _reg_case
                if self.index(_t_mov_op1):
                    continue
                self.content.append({"case": _case, "arg": _t_mov_op1})
                print(f"case:0x{_case:03x} arg@{_t_mov_op1:x}")
                continue
            if ins == "cmp" and op0 == _reg:
                if idc.print_insn_mnem(idc.next_head(ea)) == 'jnz':
                    _reg_case += int(op1.strip('h'), 16)
                    _t_cmp_yes = False
                else:
                    _t_cmp_tmp = int(op1.strip('h'), 16)
                    _t_cmp_yes = True
                continue
            if ins == "sub" and op0 == _reg:
                _reg_case += int(op1.strip('h'), 16)
                _t_cmp_yes = False
                continue

    def index(self, arg):
        for case in self.content:
            if case["arg"] == arg:
                return case["case"]
        return None

def find_next_insn(ea, insn, step=30):
    for _ in range(step):
        if idc.print_insn_mnem(ea) == insn:
            return ea
        if ea >= max_ea:
            break
        ea = idc.next_head(ea)
    return idc.BADADDR

def map_switch_jumps(_si: int):
    si = ida_nalt.switch_info_t()
    res = {}
    if ida_nalt.get_switch_info(si, _si):
        results = ida_xref.calc_switch_cases(_si, si)
        for idx in range(len(results.cases)):
            s = res.setdefault(results.targets[idx], set())
            for _idx in range(len(cases := results.cases[idx])):
                s.add(cases[_idx])
    return res

class SwitchTableX:
    def __init__(self, ea) -> None:
        self.content = []
        self.switch_func = idaapi.get_func(ea)
        self.switch_address = find_next_insn(ea, "jmp")
        print(f"switch table at {self.switch_address:x}")
        switch_info = ida_nalt.get_switch_info(self.switch_address)
        print(switch_info)
        print(switch_info.ncases)
        print(switch_info.jumps)
        print(switch_info.lowcase)
        bias = switch_info.jumps
        
        element_num = switch_info.get_jtable_size()
        element_size = switch_info.get_jtable_element_size()

        mapcase =  map_switch_jumps(self.switch_address)
        for i in range(0, element_num):
            table_entry = bias + i * element_size
            startea = switch_info.elbase + idc.get_wide_dword(table_entry)
            endea = min(
                find_next_insn(startea, "jmp", 1000),
                find_next_insn(startea, "retn", 1000),
            )
            caseid=list(mapcase.get(startea, set()))[0]
            movea = find_next_insn(startea, "mov", endea-startea)
            op1 = idc.print_operand(movea , 1)
            print(op1)
            try:
                _t_mov_op1 = int(op1.strip('h'), 16)
            except:
                _t_mov_op1 = 0xffff
            print(f"case:{caseid:x} arg:{_t_mov_op1:x}")
            self.content.append({"case": caseid, "arg": _t_mov_op1})
            
        return

    def index(self, arg):
        for case in self.content:
            if case["arg"] == arg:
                return case["case"]
        return None

record_packet = find_function("e8 ? ? ? ? 84 ? 74 ? 33 ? 38 87")
set_type(record_packet,"char __fastcall Replay_RecordPacket(__int64 this, unsigned int targetid, unsigned short opcode, const void *packet, size_t size)")
set_type(record_packet,"char __fastcall Replay_RecordPacket(__int64 this, unsigned int targetid, unsigned short opcode, const void *packet, size_t size)")

packets=CodeRefsTo(record_packet,0)
opcode={}
switch_cache={}

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
            
    pkt_size  =pkt_size.rstrip("h").lstrip("0").rjust(3,'0')
    if pkt_opcode=='0':
        func=idaapi.get_func(arg).start_ea
        if(hex(func) not in switch_cache):
            try:
                switch_cache[hex(func)]=SimpleSwitch(func)
            except:
                switch_cache[hex(func)]=SwitchTableX(func)
        pkt_opcode=switch_cache[hex(func)].index(int(pkt_size,16))
        pkt_opcode=f"{pkt_opcode:03X}"
    else:
        pkt_opcode=pkt_opcode.rstrip("h").lstrip("0").rjust(3,'0')
    
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



