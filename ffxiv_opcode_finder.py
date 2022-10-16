import idaapi
import idc
import idautils
import ida_bytes
import ida_nalt

import json

text_start=idaapi.get_imagebase()
text_end=idaapi.inf_get_max_ea()
def find_next_insn(ea,insn):
    while ea!=-1:
        if idc.print_insn_mnem(ea) == insn:
            #print("0x%x"%ea)
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
    return switch_table

def get_opcode(sig,name):
    ea=aob(sig)
    if(is_switch(ea)):
        for case in switch_table:
            if(ea>=case['start'] and ea<=case['end']):
                print(f'Opcode 0x{case["case"]:x}({case["case"]}): {name}')
        return
    func=idaapi.get_func(ea)
    if(func):ea=func.start_ea
    xrefs=idautils.XrefsTo(ea, flags=1)
    xrefs=[xref.frm for xref in xrefs if is_switch(xref.frm)]
    if(len(xrefs)>1):
        print(f"Double xref {name}")
    elif(len(xrefs)<1):
        print(f"Not found   {name}")
    else:
        xref=xrefs[0]
        for case in switch_table:
            if(xref>=case['start']and xref<=case['end']):
                print(f'Opcode 0x{case["case"]:x}({case["case"]}): {name}')

def is_switch(ea):
    if(ea>switch_func.start_ea and ea<switch_func.end_ea):
        return True
    return False

datafile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "opcode_sig.json")
with open(datafile) as f:
    signature = json.load(f)

switch_address = find_next_insn(aob(signature['ProcessZonePacketDown']),'jmp')
switch_table   = get_switch_table(switch_address)


for sig in signature['opcodes']:
    get_opcode(signature['opcodes'][sig],sig)

print('All Opcode from Signature Found')
