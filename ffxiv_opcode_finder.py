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
print("Begin FFXIVnetworkFinder...")
seg_dict = {
    idc.get_segm_name(seg): (idc.get_segm_start(seg), idc.get_segm_end(seg))
    for seg in idautils.Segments()
}
min_ea = idaapi.inf_get_min_ea()
max_ea = idaapi.inf_get_max_ea()
min_text_ea = seg_dict[".text"][0]
max_text_ea = seg_dict[".text"][1]

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
    Region = 'CN'
elif Region_s == 'ver':
    Region = 'Global'
elif Region_s == 'actoz':
    Region = 'KR'
else:
    Region='Unknown'
print(f"{Region} {version_s} {VersionID:08X} {BuildID}")

errors = {
    "SigNotFound": [],
    "IndexFailed": [],
    "FuncNotFound": [],
    "ArgvNotFound": [],
    "DoubleCase": {},
    "DoubleXref": {},
    "DoublePath": {},
}
#########
# Utils #
#########
JMP_INS = ["jmp", "jz", "ja", "jb", "jnz"]
CALL_INS = ["call"]
RET_INS = ["ret", "retn"]
CTRL_INS = JMP_INS + CALL_INS + RET_INS


def get_ctrl_target(ea):
    xrefs = list(idautils.XrefsFrom(ea, flags=1))
    return xrefs[0].to if len(xrefs) > 0 else idc.BADADDR


def find_pattern(pattern, times=1):
    address = min_text_ea
    while times>0:
        address = ida_search.find_binary(
            idc.next_head(address), max_text_ea, pattern, 16, idc.SEARCH_DOWN
        )
        times-=1
        if address == idc.BADADDR:
            return idc.BADADDR
    return address


def find_next_insn(ea, insn, step=30):
    for _ in range(step):
        if idc.print_insn_mnem(ea) == insn:
            return ea
        if ea >= max_ea:
            break
        ea = idc.next_head(ea)
    return idc.BADADDR


def find_prev_insn(ea, insn, step=10):
    for _ in range(step):
        if idc.print_insn_mnem(ea) == insn:
            return ea
        if ea <= min_ea:
            break
        ea = idc.prev_head(ea)
    return idc.BADADDR


def find_prev_ctrl(cea, up):
    while cea > up:
        if idc.print_insn_mnem(cea) in CTRL_INS:
            return cea
        cea = idc.prev_head(cea)
    return up


def find_next_ctrl(cea, down):
    while cea < down:
        if idc.print_insn_mnem(cea) in CTRL_INS:
            return cea
        cea = idc.next_head(cea)
    return down


#'ZoneClientIpc'
#'ChatServerIpc'
#'ChatClientIpc'
#'LobbyServerIpc'
#'LobbyClientIpc'

#####################
# ServerZoneIpcType #
#####################
class SwitchTable:
    def __init__(self, ea) -> None:
        self.content = []
        self.switch_func = idaapi.get_func(ea)
        self.switch_address = find_next_insn(ea, "jmp")
        print(f"switch table at {self.switch_address:x}")
        switch_info = ida_nalt.get_switch_info(self.switch_address)
        print(switch_info)
        print(switch_info.ncases)
        print(switch_info.jumps)

        bias = switch_info.jumps
        lowcase = switch_info.lowcase
        element_num = switch_info.get_jtable_size()
        element_size = switch_info.get_jtable_element_size()

        for i in range(0, element_num):
            table_entry = bias + i * element_size
            startea = switch_info.elbase + idc.get_wide_dword(table_entry)
            endea = min(
                find_next_insn(startea, "jmp", 1000),
                find_next_insn(startea, "retn", 1000),
            )
            print(
                f"case 0x{i+lowcase:03x}: table@{table_entry:x} jmp@{startea:x} - {endea:x}"
            )
            self.content.append({"case": i + lowcase, "start": startea, "end": endea})
        return

    def in_switch(self, ea) -> bool:
        return (
            True
            if ea > self.switch_func.start_ea and ea < self.switch_func.end_ea
            else False
        )

    def index(self, ea) -> list:
        maybe = []
        if self.in_switch(ea):
            maybe = [
                case["case"]
                for case in self.content
                if (ea >= case["start"] and ea <= case["end"])
            ]
        return maybe


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


class CallTable:
    def __init__(self, func_address) -> None:
        self.content = []
        self.call_fanc = idaapi.get_func(func_address)
        self.init_send_table(func_address)
        self.content.sort(key=lambda x: x["case"])
        print("Sorted CallTable")
        for i in self.content:
            print(f"Code 0x{i['case']:03x}: between@{i['start']:x} - {i['end']:x}")

    def init_send_table(self, ea):
        call_ea = ea
        func = idaapi.get_func(ea)
        if not func:
            xrefs = [xref.frm for xref in idautils.XrefsTo(ea, 0) if xref.iscode == 1]
            for xref in xrefs:
                self.init_send_table(xref)
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
                break
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
                    self.add_send_opcode(
                        op,
                        find_prev_ctrl(ea, func.start_ea),
                        find_next_ctrl(ea, func.end_ea),
                    )
                    break
                ea = idc.prev_head(ea)
            return
        else:
            for xref in idautils.XrefsTo(func.start_ea, 0):
                if xref.iscode == 1:
                    self.init_send_table(xref.frm)
            return

    def add_send_opcode(self, op, start, end):
        # print(f"Code 0x{op:03x}: between@{start:x} - {end:x}")
        self.content.append({"case": op, "start": start, "end": end})

    def index(self, ea):
        maybe = [i["case"] for i in self.content if ea >= i["start"] and ea < i["end"]]
        return list(set(maybe))


class ServerZoneIpcType:
    def __init__(self, config) -> None:
        self.config = config.content["ServerZoneIpcType"]

        self.content = {}
        self.table = SwitchTable(self.config["__init__"]["ProcessZonePacketDown"])
        del self.config["__init__"]["ProcessZonePacketDown"]
        self.funcs = {}
        for func in self.config["__init__"]:
            if self.config["__init__"][func]:
                self.funcs[func] = SimpleSwitch(self.config["__init__"][func])
        del self.config["__init__"]
        print("ServerZone Inited...")
        for name in self.config:
            if type(self.config[name]) == int:
                self.find_in_table(self.config[name], name)
            elif type(self.config[name]) == dict:
                if "Param" in self.config[name]:
                    func = self.config[name]["Function"]
                    argv = self.config[name]["Param"]
                    self.find_in_simple(func, argv, name)

    def find_in_simple(self, func, argv, name):
        if func not in self.funcs:
            errors["FuncNotFound"].append(name)
            return False
        op = self.funcs[func].index(argv)
        if not op:
            errors["ArgvNotFound"].append(name)
            return False
        self.content[name] = op
        print(f'Opcode 0x{op:03x}({op:03d}): {name}')
        return True

    def find_in_table_result(self, ea, name):
        maybe = self.table.index(ea)
        if len(maybe) > 0:
            if len(maybe) > 1:
                print(f"{name} Double Case")
                if name not in errors["DoubleCase"]:
                    errors["DoubleCase"][name] = maybe
            for op in maybe:
                print(
                    f'Opcode 0x{op:03x}({op:03d}): {name} {"?(Double Case)"if(len(maybe)>1)else "?(Double Xref)"if(name in self.content)else""}'
                )
                if name not in self.content:
                    self.content[name] = op
                else:
                    if name not in errors["DoubleXref"]:
                        errors["DoubleXref"][name] = [self.content[name]] + maybe
                    else:
                        errors["DoubleXref"][name] += maybe
            return True
        else:
            return False

#todo 递归层数检查
    def find_in_table_process(self, ea, name):
        print(f'{name} 0x{ea:03x}')
        if idaapi.segtype(ea) != idaapi.SEG_CODE:
            return False
        func = idaapi.get_func(ea)
        if func:
            ea = func.start_ea
        xrefs_all = list(idautils.XrefsTo(ea, flags=1))
        if len(xrefs_all) <= 0:
            return False
        xrefs = [xref.frm for xref in xrefs_all if self.table.in_switch(xref.frm)]
        if len(xrefs) < 1:
            if functools.reduce(
                lambda a, b: a or b,
                [self.find_in_table_process(xref.frm, name) for xref in xrefs_all],
            ):
                return True
            else:
                return False
        else:
            ea = xrefs[0]
            return self.find_in_table_result(ea, name)

    def find_in_table(self, ea, name):
        if self.find_in_table_result(ea, name):
            return True
        if self.find_in_table_process(ea, name):
            return True
        print(f"{name} NotFound")
        errors["IndexFailed"].append(name)
        return False


class ClientZoneIpcType:
    def __init__(self, config) -> None:
        self.config = config.content["ClientZoneIpcType"]
        self.content = {}
        self.table = CallTable(self.config["__init__"]["ProcessZonePacketUp"])
        del self.config["__init__"]["ProcessZonePacketUp"]
        print("ClientZone Inited...")
        for name in self.config:
            if type(self.config[name]) == int:
                self.find_in_table(self.config[name], name)

    def find_in_table(self, ea, name):
        maybe = self.table.index(ea)
        if len(maybe) > 0:
            if len(maybe) > 1:
                if name not in errors["DoublePath"]:
                    errors["DoublePath"][name] = maybe
            for op in maybe:
                print(
                    f'Opcode 0x{int(op):03x}({int(op):03d}): {name} {"?(Double Path)"if(len(maybe)>1)else""}'
                )
                if name not in self.content:
                    self.content[name] = op
            return True
        else:
            print(f"{name} NotFound")
            errors["IndexFailed"].append(name)
            return False


class ConfigReader:
    def __init__(self) -> None:
        self.path = os.path.join(
            ConfigPath,
            f"signatures.json",
        )
        with open(self.path, "r") as f:
            self.content = json.load(f)
        self.instance(self.content["ServerZoneIpcType"])
        self.instance(self.content["ClientZoneIpcType"])

    def instance(self, item):
        for i in item:
            if i == "__init__":
                self.instance(item[i])
            item[i] = self.sig2addr(item[i], i)

    def sig2addr(self, sig, name):
        address = idc.BADADDR
        _sig = None
        if type(sig) == str:
            _sig = sig
        elif type(sig) == dict:
            if "Signature" in sig:
                _sig = sig["Signature"]
            if Region == "Global" and "Global" in sig:
                return self.sig2addr(sig["Global"], name)
            elif Region == "CN" and "CN" in sig:
                return self.sig2addr(sig["CN"], name)
            elif Region == "KR" and "KR" in sig:
                return self.sig2addr(sig["KR"], name)
            if not _sig:
                return sig

        if "Index" in sig and int(sig["Index"]):
                address = find_pattern(_sig, sig["Index"]+1)
        else:
            address = find_pattern(_sig)
        if address == idc.BADADDR:
            print(f"Signature {name} Not Found")
            errors["SigNotFound"].append(name)
            return None
        else:
            if "Offset" in sig:
                address += sig["Offset"]
            if "Type" in sig and sig["Type"] == "Call":
                address = get_ctrl_target(address)
            return address


config = ConfigReader()
print(config.content)
serverzone = ServerZoneIpcType(config)
print(serverzone.content)
clientzone = ClientZoneIpcType(config)
print(clientzone.content)
print(errors)

opcodes_internal = {
    "version": BuildID,
    "region": Region,
    "lists": {
        "ServerZoneIpcType": serverzone.content,
        "ClientZoneIpcType": clientzone.content,
    },
}
opcodes = {
    "version": BuildID,
    "region": Region,
    "lists": {
        "ServerZoneIpcType": [
            {"name": i, "opcode": serverzone.content[i]} for i in serverzone.content
        ],
        "ClientZoneIpcType": [
            {"name": i, "opcode": clientzone.content[i]} for i in clientzone.content
        ],
    },
}

debugs = {"ClientCallTable": clientzone.table.content}


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
if Region == "CN":
    ipcs_filename = "Ipcs_cn.cs"
elif Region == "KR":
    ipcs_filename = "Ipcs_kr.cs"
else:
    ipcs_filename = "ipcs.cs"
opcodes_csharp_path = outpath(ipcs_filename)
errors_path = outpath("errors.json")
debugs_path = outpath("debug.json")
opcodes_path = outpath("opcodes.json")
with open(opcodes_path, "w+") as f:
    json.dump(opcodes, f, sort_keys=False, indent=4, separators=(",", ":"))
    print(f"Result saved on {opcodes_path}")
with open(opcodes_internal_path, "w+") as f:
    json.dump(opcodes_internal, f, sort_keys=False, indent=4, separators=(",", ":"))
    print(f"Result saved on {opcodes_internal_path}")

with open(errors_path, "w+") as f:
    json.dump(errors, f, sort_keys=False, indent=4, separators=(",", ":"))
    print(f"Error saved on {errors_path}")
with open(debugs_path, "w+") as f:
    json.dump(debugs, f, sort_keys=False, indent=4, separators=(",", ":"))
    print(f"Dump saved on {debugs_path}")

template_path = os.path.join(ConfigPath, f"machina.template")
mtemplate = []
mresult = []
with open(template_path, "r") as f:
    mtemplate = f.readlines()
for l in mtemplate:
    opcode_temp = re.match(r".+(?P<opcode_name>\{.+\})", l).groupdict()["opcode_name"]
    opcode_name = opcode_temp[1:-1]
    for op in (
        opcodes["lists"]["ServerZoneIpcType"] + opcodes["lists"]["ClientZoneIpcType"]
    ):
        if op["name"] == opcode_name:
            l = l.replace(opcode_temp, f"{op['opcode']:X}")
            break
    mresult.append(l)
with open(outpath("machina.txt"), "w+") as f:
    f.writelines(mresult)
print(f'Gen machina.txt on {outpath("machina.txt")}')


def get_enum_textblock(name, enums, ntype, indent):
    res = [f"public enum {name} : {ntype}", "{"]
    if len(enums) > 0:
        res += [f"    {k} = 0x{enums[k]:04X}," for k in enums]
    else:
        res += ['']
    res += ['};', '']
    return list(map(lambda l: " " * indent + l, res))


ipcs_line = [
    "// Generated by https://github.com/gamous/FFXIVNetworkOpcodes",
    f"namespace FFXIVOpcodes.{Region}",
    "{",
]
ipcs_line += get_enum_textblock("ServerLobbyIpcType", {}, 'ushort', 4)
ipcs_line += get_enum_textblock("ClientLobbyIpcType", {}, 'ushort', 4)
ipcs_line += get_enum_textblock("ServerZoneIpcType", serverzone.content, 'ushort', 4)
ipcs_line += get_enum_textblock("ClientLobbyIpcType", clientzone.content, 'ushort', 4)
ipcs_line += get_enum_textblock("ServerChatIpcType", {}, 'ushort', 4)
ipcs_line += get_enum_textblock("ClientChatIpcType", {}, 'ushort', 4)
ipcs_line += ["}"]
ipcs_line = list(map(lambda l: l + "\n", ipcs_line))
with open(opcodes_csharp_path, "w+") as f:
    f.writelines(ipcs_line)
print(f'Gen ipcs on {opcodes_csharp_path,}')
