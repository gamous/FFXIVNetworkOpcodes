import idaapi
import idc
import idautils
import ida_bytes
import ida_nalt

import json,functools

text_start=idaapi.get_imagebase()
text_end=idaapi.inf_get_max_ea()
def find_next_insn(ea,insn):
    while ea!=-1:
        if idc.print_insn_mnem(ea) == insn:
            return ea
        ea=next_head(ea)

def aob(pattern):
    address = idc.find_binary(text_start,SEARCH_DOWN,pattern)
    return address

def get_switch_table(switch_address):
    print(switch_address)
    switch_func = idaapi.get_func(switch_address)
    switch_info = ida_nalt.get_switch_info(switch_address)
    print(switch_info)
    print(switch_info.ncases)
    print(switch_info.jumps)
    loc=switch_info.jumps
    lowcase =switch_info.lowcase
    element_num=switch_info.get_jtable_size()
    element_size=switch_info.get_jtable_element_size()
    switch_table = []
    for i in range(0,element_num):
        table_entry=loc+i*element_size
        startea=switch_info.elbase+idc.get_wide_dword(table_entry)
        endea = find_next_insn(startea,'jmp')
        print(f"case 0x{i+lowcase:x}: table@{table_entry:x} jmp@{startea:x} - {endea:x}")
        switch_table.append({'case':i+lowcase,'start':startea,'end':endea})
    return switch_table,switch_func

def get_switch_case(ea):
    maybe = []
    if(is_switch(ea)):
        maybe = [case["case"] for case in switch_table if(ea>=case['start'] and ea<=case['end'])]
    return maybe

opcodes={}
def get_opcode(ea,name):
    maybe = get_switch_case(ea)
    if(len(maybe)>0):
        if(len(maybe)>1):print(f'{name} Double Case')
        for op in maybe:
            print(f'Opcode 0x{op:03x}({op:03d}): {name} {"?(Double Case)"if(len(maybe)>1)else "?(Double Xref)"if(name in opcodes)else""}')
            if(name not in opcodes): opcodes[name]=op
        return True
    else:
        return False

def get_opcode_from_addr(ea,name):
    func=idaapi.get_func(ea)
    if(func):ea=func.start_ea
    xrefs_all=list(idautils.XrefsTo(ea, flags=1))
    if(len(xrefs_all)<=0):
        return False
    xrefs=[xref.frm for xref in xrefs_all if is_switch(xref.frm)]
    if(len(xrefs)<1):
        if(functools.reduce(lambda a,b:a or b,[get_opcode_from_addr(xref.frm,name) for xref in xrefs_all])):
            return True
        else:
            return False
    else:
        ea=xrefs[0]
        return get_opcode(ea,name)

def get_opcode_from_sig(sig,name):
    ea=aob(sig)
    #in_swich
    if(get_opcode(ea,name)):
        return True
    if(get_opcode_from_addr(ea,name)):
        return True
    return False

def is_switch(ea):
    if(ea>switch_func.start_ea and ea<switch_func.end_ea):
        return True
    return False

datafile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "opcode_sig.json")
with open(datafile) as f:
    signature = json.load(f)

switch_address = find_next_insn(aob(signature['ProcessZonePacketDown']),'jmp')
switch_table,switch_func = get_switch_table(switch_address)

for sig_name in signature['opcodes']:
    if(not get_opcode_from_sig(signature['opcodes'][sig_name],sig_name)):
        print(f"Cannot found {sig_name}")
print(opcodes)
print('All Opcode from Signature Found')