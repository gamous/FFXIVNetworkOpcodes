import idaapi
import idc
import idautils
import ida_bytes
import ida_nalt

import os
import json
import functools

text_start = idaapi.get_imagebase()
text_end = idaapi.inf_get_max_ea()

# Utils
def find_next_insn(ea, insn, step=30):
    for _ in range(step):
        if idc.print_insn_mnem(ea) == insn:
            return ea
        ea = idc.next_head(ea)
        if ea == idc.BADADDR:
            return ea
    return idc.BADADDR


def find_prev_insn(ea, insn, step=10):
    for _ in range(step):
        if idc.print_insn_mnem(ea) == insn:
            return ea
        ea = idc.prev_head(ea)
    return idc.BADADDR


def find_prev_ctrl(cea, up):
    while cea > up:
        if idc.print_insn_mnem(cea) in ["jmp", "jz", "ja", "jb", "call", "ret", "retn"]:
            return cea
        cea = idc.prev_head(cea)
    return up


def find_next_ctrl(cea, down):
    while cea < down:
        if idc.print_insn_mnem(cea) in ["jmp", "jz", "ja", "jb", "call", "ret", "retn"]:
            return cea
        cea = idc.next_head(cea)
    return down


def aob(pattern):
    address = idc.find_binary(text_start, SEARCH_DOWN, pattern)
    return address


error_opcodes = {"NotFound": {}, "DoubleCase": {}, "DoubleXref": {}, "DoublePath": {}}

###################
# ServerZoneIpcType#
###################
switch_table = []
server_opcodes = {}


def init_switch_table(switch_address):
    print(switch_address)
    switch_func = idaapi.get_func(switch_address)
    switch_info = ida_nalt.get_switch_info(switch_address)
    print(switch_info)
    print(switch_info.ncases)
    print(switch_info.jumps)
    loc = switch_info.jumps
    lowcase = switch_info.lowcase
    element_num = switch_info.get_jtable_size()
    element_size = switch_info.get_jtable_element_size()
    for i in range(0, element_num):
        table_entry = loc + i * element_size
        startea = switch_info.elbase + idc.get_wide_dword(table_entry)
        endea = find_next_insn(startea, "jmp", 1000)
        print(
            f"case 0x{i+lowcase:x}: table@{table_entry:x} jmp@{startea:x} - {endea:x}"
        )
        switch_table.append({"case": i + lowcase, "start": startea, "end": endea})
    return


def get_switch_case(ea):
    maybe = []
    if is_switch(ea):
        maybe = [
            case["case"]
            for case in switch_table
            if (ea >= case["start"] and ea <= case["end"])
        ]
    return maybe


def is_switch(ea):
    if ea > switch_func.start_ea and ea < switch_func.end_ea:
        return True
    return False


def get_opcode(ea, name):
    maybe = get_switch_case(ea)
    if len(maybe) > 0:
        if len(maybe) > 1:
            print(f"{name} Double Case")
            if name not in error_opcodes["DoubleCase"]:
                error_opcodes["DoubleCase"][name] = maybe
        for op in maybe:
            print(
                f'Opcode 0x{op:03x}({op:03d}): {name} {"?(Double Case)"if(len(maybe)>1)else "?(Double Xref)"if(name in server_opcodes)else""}'
            )
            if name not in server_opcodes:
                server_opcodes[name] = op
            else:
                if name not in error_opcodes["DoubleXref"]:
                    error_opcodes["DoubleXref"][name] = [server_opcodes[name]] + maybe
                else:
                    error_opcodes["DoubleXref"][name] += maybe
        return True
    else:
        return False


def get_opcode_from_addr(ea, name):
    func = idaapi.get_func(ea)
    if func:
        ea = func.start_ea
    xrefs_all = list(idautils.XrefsTo(ea, flags=1))
    if len(xrefs_all) <= 0:
        return False
    xrefs = [xref.frm for xref in xrefs_all if is_switch(xref.frm)]
    if len(xrefs) < 1:
        if functools.reduce(
            lambda a, b: a or b,
            [get_opcode_from_addr(xref.frm, name) for xref in xrefs_all],
        ):
            return True
        else:
            return False
    else:
        ea = xrefs[0]
        return get_opcode(ea, name)


def get_opcode_from_sig(sig, name):
    ea = aob(sig)
    # in_swich
    if get_opcode(ea, name):
        return True
    if get_opcode_from_addr(ea, name):
        return True
    return False


###################
# ClientZoneIpcType#
###################
send_table = {}
client_opcodes = {}


def add_send_opcode(start, end, op):
    global send_table
    print(f"Opcode 0x{op:03x}({op:03d}) @{start:x} - {end:x}")
    if str(op) in send_table:
        send_table[str(op)] += [(start, end)]
    else:
        send_table[str(op)] = [(start, end)]


def init_send_table(ea):
    call_ea = ea
    func = idaapi.get_func(ea)
    if not func:
        xrefs = [xref.frm for xref in idautils.XrefsTo(ea, 0) if xref.iscode == 1]
        for xref in xrefs:
            init_send_table(xref)
        return
    op_var = ""
    # find lea rdx [opcode] between func.start-call
    ea = call_ea
    while ea > func.start_ea:
        if (
            idc.print_insn_mnem(ea) == "lea"
            and idc.print_operand(ea, 0) == "rdx"
            and idc.get_operand_type(ea, 1) == idaapi.o_displ
        ):
            op_var = idc.print_operand(ea, 1)
        ea = idc.prev_head(ea)
    if op_var != "":
        # find mov [opcode] imm between func.start-call
        ea = call_ea
        while ea > func.start_ea:
            if (
                idc.print_insn_mnem(ea) == "mov"
                and idc.print_operand(ea, 0) == op_var
                and idc.get_operand_type(ea, 1) == idaapi.o_imm
            ):
                op = idc.print_operand(ea, 1)
                op = op.replace("h", "")
                if op == "":
                    return
                op = int(op, 16)
                add_send_opcode(
                    find_prev_ctrl(ea, func.start_ea),
                    find_next_ctrl(ea, func.end_ea),
                    op,
                )
            ea = idc.prev_head(ea)
        return
    else:
        xrefs = [
            xref.frm for xref in idautils.XrefsTo(func.start_ea, 0) if xref.iscode == 1
        ]
        for xref in xrefs:
            init_send_table(xref)
        return


def get_send_from_sig(sig, name):
    ea = aob(sig)
    maybe = []
    for op in send_table:
        ranges = send_table[op]
        for r in ranges:
            if ea > r[0] and ea < r[1]:
                maybe.append(int(op))
    maybe = list(set(maybe))
    if len(maybe) > 0:
        if len(maybe) > 1:
            if name not in error_opcodes["DoublePath"]:
                error_opcodes["DoublePath"][name] = maybe
        for op in maybe:
            print(
                f'Opcode 0x{int(op):03x}({int(op):03d}): {name} {"?(Double Path)"if(len(maybe)>1)else""}'
            )
            if name not in client_opcodes:
                client_opcodes[name] = op
        return True
    else:
        return False


###
datafile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "signatures.json")
resultfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "opcodes.json")
errorfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "errors.json")
with open(datafile, "r") as f:
    signature = json.load(f)

packet_down = aob(signature["ProcessZonePacketDown"])
packet_up = aob(signature["ProcessZonePacketUp"])

switch_address = find_next_insn(packet_down, "jmp")
switch_func = idaapi.get_func(switch_address)
init_switch_table(switch_address)
init_send_table(packet_up)
for op in send_table:
    print(f"Opcode 0x{int(op):03x}({int(op):03d}): {send_table[(str(op))]}")


for sig_name in signature["ServerZoneIpcType"]:
    if not get_opcode_from_sig(signature["ServerZoneIpcType"][sig_name], sig_name):
        print(f"Cannot found {sig_name}")
        error_opcodes["NotFound"][sig_name] = []

for sig_name in signature["ClientZoneIpcType"]:
    if not get_send_from_sig(signature["ClientZoneIpcType"][sig_name], sig_name):
        print(f"Cannot found {sig_name}")
        error_opcodes["NotFound"][sig_name] = []

print(server_opcodes)
print(client_opcodes)
print(error_opcodes)
if len(error_opcodes["NotFound"]) > 0:
    print("Some signature failed to find opcode!")
else:
    print("All Opcode from signature Found!")

opcodes = {
    "version": signature["Version"],
    "region": signature["Region"],
    "lists": {
        "ServerZoneIpcType": [
            {"name": i, "opcode": server_opcodes[i]} for i in server_opcodes
        ],
        "ClientZoneIpcType": [
            {"name": i, "opcode": client_opcodes[i]} for i in client_opcodes
        ],
    },
}

with open(resultfile, "w+") as f:
    json.dump(opcodes, f, sort_keys=False, indent=4, separators=(",", ":"))
    print(f"Result saved on {resultfile}")
with open(errorfile, "w+") as f:
    json.dump(error_opcodes, f, sort_keys=False, indent=4, separators=(",", ":"))
    print(f"Error saved on {errorfile}")
