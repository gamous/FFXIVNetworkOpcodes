import idaapi
import idc
import idautils
import ida_bytes
import ida_nalt
import ida_xref
import ida_search
import ida_ua
import ida_hexrays
import ida_funcs
import ida_gdl
import ida_idp
import ida_allins
import os
import json
import functools
import re
import typing
import copy
from ida_hexrays import *

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
        _splited = s.split("_")
        BuildID = _splited[1].replace("/", ".")
        VersionID = int(_splited[0][_splited[0].index("rev") + 3:])
        break
for s in slist_s:
    if r"ffxiv_dx11.pdb" in s:
        if "GenCh" in s: # Why?
            Region_s = "shanda"
            version_s = s.split('\\')[4].split('_')[1]
            break

        Region_s,version_s = s.split('\\')[4].split('_')
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
JMP_INS = ["jmp", "ja", "jz", "jnz", "je", "jne", "jg", "jge", "jl", "jle"]
CALL_INS = ["call"]
RET_INS = ["ret", "retn"]
CTRL_INS = JMP_INS + CALL_INS + RET_INS
EQ_TRUE_JUMPS = {"jz", "je"}
EQ_FALSE_JUMPS = {"jnz", "jne"}
CONDITIONAL_JUMPS = {
    ida_allins.NN_ja,
    ida_allins.NN_jae,
    ida_allins.NN_jb,
    ida_allins.NN_jbe,
    ida_allins.NN_jg,
    ida_allins.NN_jge,
    ida_allins.NN_jl,
    ida_allins.NN_jle,
    ida_allins.NN_jz,
    ida_allins.NN_jnz,
    ida_allins.NN_jne,
    ida_allins.NN_je,
}
EQ_TRUE_JUMP_TYPES = {ida_allins.NN_jz, ida_allins.NN_je}
EQ_FALSE_JUMP_TYPES = {ida_allins.NN_jnz, ida_allins.NN_jne}
RETURN_TYPES = {ida_allins.NN_retn, ida_allins.NN_retf}
JUMP_TYPES = {ida_allins.NN_jmp, ida_allins.NN_jmpfi, ida_allins.NN_jmpni, ida_allins.NN_jmpshort}
CALL_TYPES = {ida_allins.NN_call, ida_allins.NN_callfi, ida_allins.NN_callni}
LINEAR_JUMP_TYPES = {
    ida_allins.NN_jmp,
    ida_allins.NN_jmpfi,
    ida_allins.NN_jmpni,
    ida_allins.NN_jmpshort,
    ida_allins.NN_ja,
    ida_allins.NN_jz,
    ida_allins.NN_jnz,
    ida_allins.NN_jne,
    ida_allins.NN_je,
    ida_allins.NN_jg,
    ida_allins.NN_jge,
    ida_allins.NN_jl,
    ida_allins.NN_jle,
}
LINEAR_RETURN_TYPES = {ida_allins.NN_retn}
LINEAR_CONTROL_TYPES = LINEAR_JUMP_TYPES | CALL_TYPES | LINEAR_RETURN_TYPES
REG_R8 = ida_idp.str2reg("r8w")
REG_R10 = ida_idp.str2reg("r10d")
REG_RSP = ida_idp.str2reg("rsp")
REG_EAX = ida_idp.str2reg("eax")
REG_RDX = ida_idp.str2reg("rdx")


def get_ctrl_target(ea):
    xrefs = [xref for xref in idautils.XrefsFrom(ea, flags=1) if xref.iscode]
    return xrefs[0].to if len(xrefs) > 0 else idc.BADADDR


def get_branch_target(ea):
    target = idc.get_operand_value(ea, 0)
    return target if target != idc.BADADDR else get_ctrl_target(ea)


@functools.cache
def _find_pattern_cached(pattern, times):
    address = min_text_ea
    while times > 0:
        address = ida_bytes.find_bytes(pattern, range_start=idc.next_head(address), range_end=max_text_ea)
        times -= 1
        if address == idc.BADADDR:
            return idc.BADADDR
    return address


def find_pattern(pattern, times=1):
    return _find_pattern_cached(pattern, times)


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
        if is_control_insn(cea):
            return cea
        cea = idc.prev_head(cea)
    return up


def find_next_ctrl(cea, down):
    while cea < down:
        if is_control_insn(cea):
            return cea
        cea = idc.next_head(cea)
    return down


def is_control_insn(ea):
    insn = ida_ua.insn_t()
    return ida_ua.decode_insn(insn, ea) > 0 and insn.itype in LINEAR_CONTROL_TYPES

class OperandLine(typing.NamedTuple):
    ea: int
    insn: str
    itype: int
    op1: int
    op2: int
    val1: int
    val2: int

    a = property(lambda self: (self.op1, self.val1))
    b = property(lambda self: (self.op2, self.val2))


class StorageRef(typing.NamedTuple):
    location: tuple[int, int, int, int]
    text: str


class EventPacketResolver:
    def __init__(self, func_ea, sender):
        self.func = ida_funcs.get_func(func_ea)
        if not self.func:
            raise ValueError(f"Could not find function at {func_ea:x}")
        self.sender = sender
        self._ops = {}
        self.blocks = list(ida_gdl.FlowChart(self.func))
        self.block_by_start = {block.start_ea: block for block in self.blocks}
        self.addr_to_block = {}
        for block in self.blocks:
            ea = block.start_ea
            while ea != idc.BADADDR and ea < block.end_ea:
                self.addr_to_block[ea] = block
                ea = idc.next_head(ea, block.end_ea)

    def resolve(self):
        set_vals = self._sender_opcode_sets()
        for ea, conds in self._find_cond(self.func.start_ea, set(set_vals)):
            opcode = set_vals[ea]
            min_val, max_val = self._range_from_conditions(ea, conds)
            yield opcode, min_val, max_val, conds

    def _op(self, ea):
        if ea not in self._ops:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) > 0:
                mnem = insn.get_canon_mnem()
                itype = insn.itype
            else:
                mnem = idc.print_insn_mnem(ea)
                itype = -1
            self._ops[ea] = OperandLine(
                ea,
                mnem,
                itype,
                idc.get_operand_type(ea, 0),
                idc.get_operand_type(ea, 1),
                idc.get_operand_value(ea, 0),
                idc.get_operand_value(ea, 1),
            )
        return self._ops[ea]

    def _sender_opcode_sets(self):
        set_vals = {}
        for call_ea in self._sender_calls():
            for ea, opcode in self._find_set(call_ea, idaapi.o_reg, REG_RDX):
                if ea in set_vals and set_vals[ea] != opcode:
                    raise ValueError(f"Conflicting opcode values at {ea:x}: {set_vals[ea]:x} vs {opcode:x}")
                set_vals[ea] = opcode
        return set_vals

    def _sender_calls(self):
        for ea in idautils.FuncItems(self.func.start_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) <= 0:
                continue
            if insn.itype == ida_allins.NN_call and get_branch_target(ea) == self.sender:
                yield ea

    def _find_set(self, ea, operand_type, operand_value):
        analyzed = set()
        to_analyze = [ea]

        while to_analyze:
            cur = to_analyze.pop()
            if cur in analyzed:
                continue
            analyzed.add(cur)

            op = self._op(cur)
            if op.op1 == operand_type and op.val1 == operand_value:
                if op.itype == ida_allins.NN_lea:
                    if op.op2 == idaapi.o_displ:
                        yield from self._find_set(cur, idaapi.o_displ, op.val2)
                        continue
                    raise ValueError(f"Unexpected instruction at {hex(cur)}")
                if op.itype == ida_allins.NN_mov:
                    if op.op2 == idaapi.o_imm:
                        yield cur, op.val2
                        continue
                    raise ValueError(f"Unexpected instruction at {hex(cur)}")

            for xref in idautils.XrefsTo(cur):
                if self._is_backward_flow_xref(xref) and xref.frm not in analyzed and xref.frm not in to_analyze:
                    to_analyze.append(xref.frm)

    def _find_cond(self, start_ea, end_eas):
        start_block = self.addr_to_block.get(start_ea)
        if not start_block:
            return

        seen = set()
        work = [(start_block.start_ea, [], None)]

        while work:
            block_start, conds, last_cond = work.pop()
            state_key = (block_start, tuple(conds), last_cond.ea if last_cond else None)
            if state_key in seen:
                continue
            seen.add(state_key)

            block = self.block_by_start.get(block_start)
            if not block:
                continue

            out_last_cond = last_cond
            ea = block.start_ea
            while ea != idc.BADADDR and ea < block.end_ea:
                if ea in end_eas:
                    yield ea, conds
                    break

                op = self._op(ea)
                if op.itype in (ida_allins.NN_test, ida_allins.NN_cmp):
                    out_last_cond = op
                ea = idc.next_head(ea, block.end_ea)
            else:
                for succ_start, succ_conds, succ_last_cond in self._successor_cond_states(block, conds, out_last_cond):
                    work.append((succ_start, succ_conds, succ_last_cond))

    def _successor_cond_states(self, block, conds, last_cond):
        last_ea = self._last_insn(block)
        if last_ea == idc.BADADDR:
            return []

        op = self._op(last_ea)
        if op.itype in RETURN_TYPES:
            return []
        if op.itype in JUMP_TYPES:
            target = get_branch_target(last_ea)
            return [(target, conds, last_cond)] if target in self.block_by_start else []

        if op.itype in CONDITIONAL_JUMPS:
            target = get_branch_target(last_ea)
            fallthrough = self._fallthrough(last_ea, block)
            out = []
            if target in self.block_by_start:
                out.append((target, conds + [(last_ea, op.itype, last_cond, False)], last_cond))
            if fallthrough in self.block_by_start:
                out.append((fallthrough, conds + [(last_ea, op.itype, last_cond, True)], last_cond))
            return out

        return [(succ.start_ea, conds, last_cond) for succ in block.succs() if succ.start_ea in self.block_by_start]

    def _fallthrough(self, ea, block):
        nxt = idc.next_head(ea, block.end_ea)
        if nxt != idc.BADADDR and nxt < block.end_ea:
            return nxt
        branch_target = get_branch_target(ea)
        for succ in block.succs():
            if succ.start_ea != branch_target:
                return succ.start_ea
        return idc.BADADDR

    def _last_insn(self, block):
        ea = block.start_ea
        last = idc.BADADDR
        while ea != idc.BADADDR and ea < block.end_ea:
            last = ea
            ea = idc.next_head(ea, block.end_ea)
        return last

    def _range_from_conditions(self, ea, conds):
        if len(conds) == 0 or conds[-1][2] is None:
            raise ValueError(f"No condition found for event packet at {hex(ea)}")
        last_op = conds[-1][2]
        if last_op.op2 != idaapi.o_imm:
            raise ValueError(f"Last condition is not an immediate value at {hex(ea)}")

        max_val = 255
        min_val = 0
        for ea_, insn, op, is_def in reversed(conds):
            if op.a != last_op.a:
                break
            if op.op2 != idaapi.o_imm:
                continue
            desc = self._condition_desc(ea_, insn, op, is_def)
            match desc:
                case "<":
                    max_val = min(max_val, op.val2 - 1)
                case ">":
                    min_val = max(min_val, op.val2 + 1)
                case "<=":
                    max_val = min(max_val, op.val2)
                case ">=":
                    min_val = max(min_val, op.val2)
                case "==":
                    max_val = min(max_val, op.val2)
                    min_val = max(min_val, op.val2)
                    break
        return min_val, max_val

    def _condition_desc(self, ea, branch_itype, op, is_def):
        if op.itype == ida_allins.NN_test:
            raise ValueError(f"Should not have test instruction at {hex(ea)}")
        if op.itype != ida_allins.NN_cmp:
            raise ValueError(f"Unexpected instruction at {hex(ea)}")

        if branch_itype == ida_allins.NN_jge:
            return "<" if is_def else ">="
        if branch_itype == ida_allins.NN_jle:
            return ">" if is_def else "<="
        if branch_itype == ida_allins.NN_jg:
            return "<=" if is_def else ">"
        if branch_itype == ida_allins.NN_jl:
            return ">=" if is_def else "<"
        if branch_itype == ida_allins.NN_ja:
            return "<=" if is_def else ">"
        if branch_itype == ida_allins.NN_jae:
            return "<" if is_def else ">="
        if branch_itype == ida_allins.NN_jb:
            return ">=" if is_def else "<"
        if branch_itype == ida_allins.NN_jbe:
            return ">" if is_def else "<="
        if branch_itype == ida_allins.NN_je or branch_itype == ida_allins.NN_jz:
            return "!=" if is_def else "=="
        if branch_itype == ida_allins.NN_jne or branch_itype == ida_allins.NN_jnz:
            return "==" if is_def else "!="
        raise ValueError(f"Unexpected instruction at {hex(ea)}")

    def _is_forward_flow_xref(self, xref):
        return (
            xref.type in (ida_xref.fl_JN, ida_xref.fl_JF, ida_xref.fl_F)
            and self.func.contains(xref.to)
        )

    def _is_backward_flow_xref(self, xref):
        return (
            xref.type in (ida_xref.fl_JN, ida_xref.fl_JF, ida_xref.fl_F)
            and self.func.contains(xref.frm)
        )


# 感谢头子 :))))
def find_event_packets(func_ea, sender):
    yield from EventPacketResolver(func_ea, sender).resolve()


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
        self.switch_func = ida_funcs.get_func(ea)
        if not self.switch_func:
            raise ValueError(f"Could not find function at {ea:x}")

        potential_switches = self._find_switches()
        if not potential_switches:
            print(f"No valid switch table found for function at {ea:x}")
            return

        self.switch_address, switch_info, results = max(
            potential_switches,
            key=lambda item: item[1].ncases,
        )

        print(f"Selected switch table at {self.switch_address:x} with {switch_info.ncases} cases")
        print(switch_info)
        print(f"Number of cases: {switch_info.ncases}")
        print(f"Jumps address: {switch_info.jumps:x}")

        target_to_cases = self._target_to_cases(results)
        case_targets = set(target_to_cases)
        self.blocks = list(ida_gdl.FlowChart(self.switch_func))

        for target, case_list in target_to_cases.items():
            ranges = self._handler_ranges(target, case_targets)
            for case_val in case_list:
                for start, end in ranges:
                    print(f"case 0x{case_val:03x}: block@{start:x} - {end:x}")
                    self.content.append({"case": case_val, "start": start, "end": end})
        return

    def _find_switches(self):
        candidates = []
        ea = self.switch_func.start_ea
        while ea != idc.BADADDR and ea < self.switch_func.end_ea:
            switch_info = ida_nalt.get_switch_info(ea)
            if switch_info and switch_info.ncases > 0:
                try:
                    results = ida_xref.calc_switch_cases(ea, switch_info)
                except Exception as exc:
                    print(f"Failed to calculate switch cases at {ea:x}: {exc}")
                else:
                    if results and len(results.cases) > 0:
                        candidates.append((ea, switch_info, results))
            ea = idc.next_head(ea, self.switch_func.end_ea)
        return candidates

    def _target_to_cases(self, results):
        target_to_cases = {}
        for idx in range(len(results.cases)):
            target = results.targets[idx]
            case_values = target_to_cases.setdefault(target, [])
            cases = results.cases[idx]
            for case_idx in range(len(cases)):
                case_values.append(cases[case_idx])
        return target_to_cases

    def _block_for_ea(self, ea):
        for block in self.blocks:
            if block.start_ea <= ea < block.end_ea:
                return block
        return None

    def _handler_ranges(self, target, case_targets):
        start_block = self._block_for_ea(target)
        if not start_block:
            return [(target, idc.next_head(target, self.switch_func.end_ea))]

        ranges = []
        work = [start_block]
        seen = set()
        while work:
            block = work.pop()
            if block.start_ea in seen:
                continue
            seen.add(block.start_ea)
            ranges.append((max(target, block.start_ea), block.end_ea))

            if self._ends_with_terminal_jump(block):
                continue

            for succ in block.succs():
                if not self.switch_func.contains(succ.start_ea):
                    continue
                if succ.start_ea in case_targets and succ.start_ea != start_block.start_ea:
                    continue
                work.append(succ)

        return sorted(ranges)

    def _ends_with_terminal_jump(self, block):
        last = self._last_insn(block)
        if last == idc.BADADDR:
            return True
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, last) <= 0:
            return True
        return insn.itype in RETURN_TYPES or insn.itype in JUMP_TYPES

    def _last_insn(self, block):
        ea = block.start_ea
        last = idc.BADADDR
        while ea != idc.BADADDR and ea < block.end_ea:
            last = ea
            ea = idc.next_head(ea, block.end_ea)
        return last

    def in_switch(self, ea) -> bool:
        return (
            True
            if ea > self.switch_func.start_ea and ea < self.switch_func.end_ea
            else False
        )

    def index(self, ea) -> list:
        maybe = set()
        if self.in_switch(ea):
            for case in self.content:
                if case["start"] <= ea < case["end"]:
                    maybe.add(case["case"])
        return sorted(maybe)


class CaseExpr(typing.NamedTuple):
    base_reg: int
    addend: int = 0

    def sub(self, value):
        return CaseExpr(self.base_reg, self.addend - value)

    def equals(self, value):
        if self.base_reg != REG_R8:
            return None
        return (value - self.addend) & 0xFFFF


class DisasmSwitchResolver:
    def __init__(self, switch_address):
        self.content = []
        self.switch_func = ida_funcs.get_func(switch_address)
        if not self.switch_func:
            print(f"Error: Could not find function at 0x{switch_address:x}")
            return

        self.blocks = list(ida_gdl.FlowChart(self.switch_func))
        self.block_by_start = {block.start_ea: block for block in self.blocks}
        self.addr_to_block = {}
        for block in self.blocks:
            ea = block.start_ea
            while ea != idc.BADADDR and ea < block.end_ea:
                self.addr_to_block[ea] = block
                ea = idc.next_head(ea, block.end_ea)

        self._resolve()
        if not self.content:
            raise ValueError("DisasmSwitchResolver failed to extract any case-arg pairs")

        final_content = []
        seen_args = set()
        for item in sorted(self.content, key=lambda x: x["case"]):
            if item["arg"] not in seen_args:
                final_content.append(item)
                seen_args.add(item["arg"])
        self.content = final_content

    def index(self, arg):
        for item in self.content:
            if item["arg"] == arg:
                return item["case"]
        return None

    def _resolve(self):
        initial_state = {"regs": {}, "case": None}
        work = [(self.switch_func.start_ea, initial_state)]
        seen = set()
        found = []

        while work:
            block_start, state = work.pop()
            block = self.block_by_start.get(block_start)
            if not block:
                continue
            key = (block_start, self._state_key(state))
            if key in seen:
                continue
            seen.add(key)

            out_state, sink = self._process_block(block, state)
            if sink is not None:
                found.append(sink)

            for succ_start, succ_state in self._successor_states(block, out_state):
                if succ_start in self.block_by_start:
                    work.append((succ_start, succ_state))

        self.content = self._dedupe(found)

    def _state_key(self, state):
        regs = tuple(sorted(state["regs"].items()))
        return (regs, state.get("case"), state.get("_last_cmp_case"))

    def _copy_state(self, state):
        copied = {"regs": dict(state["regs"]), "case": state.get("case")}
        if "_last_cmp_case" in state:
            copied["_last_cmp_case"] = state["_last_cmp_case"]
        return copied

    def _dedupe(self, items):
        result = []
        seen = set()
        for item in sorted(items, key=lambda x: (x["case"], x["arg"])):
            key = (item["case"], item["arg"])
            if key in seen:
                continue
            seen.add(key)
            result.append({"case": item["case"], "arg": item["arg"]})
        return result

    def _decode(self, ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            return None
        return insn

    def _fallthrough(self, ea, block):
        nxt = idc.next_head(ea, block.end_ea)
        if nxt != idc.BADADDR and nxt < block.end_ea:
            return nxt
        for succ in block.succs():
            if succ.start_ea != get_branch_target(ea):
                return succ.start_ea
        return idc.BADADDR

    def _last_insn(self, block):
        ea = block.start_ea
        last = idc.BADADDR
        while ea != idc.BADADDR and ea < block.end_ea:
            last = ea
            ea = idc.next_head(ea, block.end_ea)
        return last

    def _expr_from_operand(self, ea, op_idx, state):
        insn = self._decode(ea)
        if not insn:
            return None
        op = insn.ops[op_idx]
        if op.type == ida_ua.o_imm:
            return op.value
        if op.type == ida_ua.o_reg:
            return state["regs"].get(self._norm_reg(op.reg))
        return None

    def _norm_reg(self, reg):
        if reg == REG_R8:
            return "r8"
        if reg == REG_R10:
            return "r10"
        if reg == REG_EAX:
            return "eax"
        return reg

    def _compute_eq_case(self, ea, state):
        left = self._expr_from_operand(ea, 0, state)
        right = self._expr_from_operand(ea, 1, state)
        if isinstance(left, CaseExpr) and isinstance(right, int):
            return left.equals(right)
        if isinstance(right, CaseExpr) and isinstance(left, int):
            return right.equals(left)
        return None

    def _process_block(self, block, state):
        state = self._copy_state(state)
        last_cmp_case = None
        pending_arg = None
        ea = block.start_ea

        while ea != idc.BADADDR and ea < block.end_ea:
            decoded = self._decode(ea)
            if not decoded:
                ea = idc.next_head(ea, block.end_ea)
                continue
            op0 = decoded.ops[0]
            op1 = decoded.ops[1]
            norm_op0 = self._norm_reg(op0.reg) if op0.type == ida_ua.o_reg else None

            if self._is_reg_reg(decoded, ida_allins.NN_movzx, REG_R8):
                state["regs"][norm_op0] = CaseExpr(REG_R8, 0)
            elif decoded.itype == ida_allins.NN_sub and norm_op0 in state["regs"] and op1.type == ida_ua.o_imm:
                expr = state["regs"][norm_op0]
                if isinstance(expr, CaseExpr):
                    state["regs"][norm_op0] = expr.sub(op1.value)
                    last_cmp_case = state["regs"][norm_op0].equals(0)
                    if last_cmp_case is not None:
                        state["_last_cmp_case"] = last_cmp_case
            elif decoded.itype == ida_allins.NN_mov and op0.type == ida_ua.o_reg:
                if op1.type == ida_ua.o_imm:
                    state["regs"][norm_op0] = op1.value
                elif op1.type == ida_ua.o_reg:
                    src = self._norm_reg(op1.reg)
                    state["regs"][norm_op0] = state["regs"].get(src)
            elif decoded.itype == ida_allins.NN_cmp:
                last_cmp_case = self._compute_eq_case(ea, state)
                if last_cmp_case is not None:
                    state["_last_cmp_case"] = last_cmp_case
            elif decoded.itype == ida_allins.NN_mov and op0.type == ida_ua.o_displ:
                if op0.phrase == REG_RSP and op1.type == ida_ua.o_imm:
                    pending_arg = op1.value
            elif decoded.itype == ida_allins.NN_call:
                if pending_arg not in (None, 0) and state.get("case") is not None:
                    return state, {"case": state["case"], "arg": pending_arg}

            ea = idc.next_head(ea, block.end_ea)

        return state, None

    def _successor_states(self, block, state):
        last = self._last_insn(block)
        if last == idc.BADADDR:
            return []

        insn = self._decode(last)
        if not insn:
            return []

        if insn.itype in RETURN_TYPES:
            return []
        if insn.itype in JUMP_TYPES:
            target = get_branch_target(last)
            return [(target, self._copy_state(state))]

        if insn.itype in CONDITIONAL_JUMPS:
            target = get_branch_target(last)
            fallthrough = self._fallthrough(last, block)
            case = state.get("_last_cmp_case")
            true_state = self._copy_state(state)
            false_state = self._copy_state(state)

            out = []
            if insn.itype in EQ_TRUE_JUMP_TYPES and case is not None:
                true_state["case"] = case
                true_state.pop("_last_cmp_case", None)
                false_state.pop("_last_cmp_case", None)
            elif insn.itype in EQ_FALSE_JUMP_TYPES and case is not None:
                false_state["case"] = case
                false_state.pop("_last_cmp_case", None)
                true_state.pop("_last_cmp_case", None)
            elif case is not None:
                true_state.pop("_last_cmp_case", None)

            if target != idc.BADADDR:
                out.append((target, true_state))
            if fallthrough != idc.BADADDR:
                out.append((fallthrough, false_state))
            return out

        return [(succ.start_ea, self._copy_state(state)) for succ in block.succs()]

    def _is_reg_reg(self, insn, itype, src_reg):
        op0 = insn.ops[0]
        op1 = insn.ops[1]
        return (
            insn.itype == itype
            and op0.type == ida_ua.o_reg
            and op1.type == ida_ua.o_reg
            and op1.reg == src_reg
        )


class CallTable:
    def __init__(self, func_address) -> None:
        self.content = []
        self.call_fanc = ida_funcs.get_func(func_address)
        self._visited = set()
        self.init_send_table(func_address)
        self.content.sort(key=lambda x: x["case"])
        print("Sorted CallTable")
        for i in self.content:
            print(f"Code 0x{i['case']:03x}: between@{i['start']:x} - {i['end']:x}")

    def init_send_table(self, ea):
        if ea in self._visited:
            return
        self._visited.add(ea)

        call_ea = ea
        func = ida_funcs.get_func(ea)
        if not func:
            xrefs = [xref.frm for xref in idautils.XrefsTo(ea, 0) if xref.iscode == 1]
            for xref in xrefs:
                self.init_send_table(xref)
            return

        opcode_storage = self._find_opcode_storage(call_ea, func.start_ea)
        if opcode_storage is not None:
            mov_ea, opcode = self._find_opcode_store(call_ea, func.start_ea, opcode_storage)
            if mov_ea is not None:
                self.add_send_opcode(
                    opcode,
                    find_prev_ctrl(mov_ea, func.start_ea),
                    find_next_ctrl(mov_ea, func.end_ea),
                )
            return
        else:
            for xref in idautils.XrefsTo(func.start_ea, 0):
                if xref.iscode == 1:
                    self.init_send_table(xref.frm)
            return

    def _decode(self, ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            return None
        return insn

    def _find_opcode_storage(self, call_ea, start_ea):
        ea = call_ea
        while ea > start_ea:
            insn = self._decode(ea)
            if insn:
                op0 = insn.ops[0]
                op1 = insn.ops[1]
                if (
                    insn.itype == ida_allins.NN_lea
                    and op0.type == ida_ua.o_reg
                    and op0.reg == REG_RDX
                    and op1.type == ida_ua.o_displ
                ):
                    return StorageRef(self._operand_location(op1), idc.print_operand(ea, 1))
            ea = idc.prev_head(ea)
        return None

    def _find_opcode_store(self, call_ea, start_ea, storage):
        ea = call_ea
        while ea > start_ea:
            insn = self._decode(ea)
            if insn:
                op0 = insn.ops[0]
                op1 = insn.ops[1]
                if (
                    insn.itype == ida_allins.NN_mov
                    and self._operand_location(op0) == storage.location
                    and idc.print_operand(ea, 0) == storage.text
                    and op1.type == ida_ua.o_imm
                ):
                    return ea, op1.value
            ea = idc.prev_head(ea)
        return None, None

    def _operand_location(self, op):
        if op.type not in (ida_ua.o_displ, ida_ua.o_mem):
            return None
        return (op.type, op.reg, op.phrase, op.addr)

    def add_send_opcode(self, op, start, end):
        # print(f"Code 0x{op:03x}: between@{start:x} - {end:x}")
        self.content.append({"case": op, "start": start, "end": end})

    def index(self, ea):
        return sorted({i["case"] for i in self.content if ea >= i["start"] and ea < i["end"]})


class ServerZoneIpcType:
    def __init__(self, config) -> None:
        self.config = config.content["ServerZoneIpcType"]

        self.content = {}
        self.table = SwitchTable(self.config["__init__"]["ProcessZonePacketDown"])
        del self.config["__init__"]["ProcessZonePacketDown"]
        self.funcs = {}
        for func in self.config["__init__"]:
            if self.config["__init__"][func]:
                print(f"Init DisasmSwitchResolver {func}")
                self.funcs[func] = DisasmSwitchResolver(self.config["__init__"][func])
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
            print(f"func {func} - {name} {argv} \n{self.funcs[func].content}")
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

    def find_in_table_process(self, ea, name, visited=None, depth=0, max_depth=64):
        if visited is None:
            visited = set()
        if ea in visited or depth > max_depth:
            return False
        next_visited = visited | {ea}
        print(f'{name} 0x{ea:03x}')
        if idaapi.segtype(ea) != idaapi.SEG_CODE:
            return False
        func = ida_funcs.get_func(ea)
        if func:
            ea = func.start_ea
        xrefs_all = list(idautils.XrefsTo(ea, flags=1))
        if len(xrefs_all) <= 0:
            return False
        xrefs = [xref.frm for xref in xrefs_all if self.table.in_switch(xref.frm)]
        if len(xrefs) < 1:
            results = [
                self.find_in_table_process(xref.frm, name, next_visited, depth + 1, max_depth)
                for xref in xrefs_all
            ]
            return any(results)
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

        # ProcessZonePacketUp 是最底层的发送函数
        base_sender_ea = self.config["__init__"]["ProcessZonePacketUp"]
        self.table = CallTable(base_sender_ea)

        # 查找 wrapper 函数（调用 ProcessZonePacketUp 的函数）
        wrapper_funcs = self.find_wrapper_functions(base_sender_ea)
        print(f"Found {len(wrapper_funcs)} potential wrapper functions")

        # 初始化事件包查找器字典
        self.event_funcs = {}
        for func_name in list(self.config.get("__init__", {}).keys()):
            if func_name == "ProcessZonePacketUp":
                continue  # 跳过基础发送函数本身

            func_ea = self.config["__init__"][func_name]
            if func_ea:
                try:
                    # 尝试为该函数找到合适的 sender（wrapper）
                    sender_ea = self.find_best_sender(func_ea, wrapper_funcs)
                    if sender_ea != idc.BADADDR:
                        # 将生成器转换为列表
                        self.event_funcs[func_name] = list(find_event_packets(func_ea, sender_ea))
                        print(f"Initialized event packet finder for {func_name} with sender@{sender_ea:x}: found {len(self.event_funcs[func_name])} entries")
                    else:
                        print(f"Could not find suitable sender for {func_name}")
                except Exception as e:
                    print(f"Failed to initialize event packet finder for {func_name}: {e}")

        if "__init__" in self.config:
            del self.config["__init__"]

        print("ClientZone Inited...")
        for name in self.config:
            config_value = self.config[name]
            if isinstance(config_value, dict):
                if "Pattern" in config_value and "ReadOffset" in config_value:
                    self.read_bytes_at_offset(config_value["Pattern"], config_value["ReadOffset"], name)
                elif "Function" in config_value and "Param" in config_value:
                    func = config_value["Function"]
                    param = config_value["Param"]
                    self.find_in_event_packets(func, param, name)
            elif type(config_value) == int:
                self.find_in_table(config_value, name)
            else:
                print(f"Invalid type in ClientZoneIpc -> {name}")

    def find_wrapper_functions(self, base_sender_ea):
        """查找所有调用 ProcessZonePacketUp 的 wrapper 函数（递归查找多层）"""
        wrappers = []

        def find_callers_recursive(ea, depth=0, max_depth=3):
            """递归查找调用链，最多3层"""
            if depth > max_depth:
                return

            for xref in idautils.XrefsTo(ea):
                if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):  # Call xrefs
                    caller_func = ida_funcs.get_func(xref.frm)
                    if caller_func and caller_func.start_ea not in wrappers:
                        wrappers.append(caller_func.start_ea)
                        print(f"Found wrapper function at {caller_func.start_ea:x} (depth={depth})")
                        # 继续向上查找
                        find_callers_recursive(caller_func.start_ea, depth + 1, max_depth)

        find_callers_recursive(base_sender_ea)
        return wrappers

    def find_best_sender(self, func_ea, wrapper_funcs):
        """为目标函数找到最合适的 sender（wrapper）函数"""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return idc.BADADDR

        # 收集目标函数调用的所有函数
        called_funcs = set()
        for item_ea in idautils.FuncItems(func.start_ea):
            if idc.print_insn_mnem(item_ea) == "call":
                target = get_ctrl_target(item_ea)
                if target != idc.BADADDR:
                    called_funcs.add(target)

        # 查找目标函数直接调用的 wrapper
        for wrapper_ea in wrapper_funcs:
            if wrapper_ea in called_funcs:
                print(f"Found direct wrapper call: {wrapper_ea:x} for function {func_ea:x}")
                return wrapper_ea

        # 如果没有直接调用，尝试查找间接调用（通过一层）
        for called_ea in called_funcs:
            called_func = ida_funcs.get_func(called_ea)
            if called_func:
                for item_ea in idautils.FuncItems(called_func.start_ea):
                    if idc.print_insn_mnem(item_ea) == "call":
                        target = get_ctrl_target(item_ea)
                        if target in wrapper_funcs:
                            print(f"Found indirect wrapper call: {target:x} (via {called_ea:x}) for function {func_ea:x}")
                            return target

        print(f"No wrapper found for function {func_ea:x}")
        return idc.BADADDR

    def find_in_event_packets(self, func, param, name):
        """使用 find_event_packets 查找 opcode"""
        if func not in self.event_funcs:
            print(f"Event function {func} not found for {name}")
            errors["FuncNotFound"].append(name)
            return False

        try:
            candidates = sorted(
                self.event_funcs[func],
                key=lambda item: (item[2] - item[1], item[1], item[2], item[0]),
            )
            for opcode, min_val, max_val, conds in candidates:
                if min_val <= param <= max_val:
                    self.content[name] = opcode
                    print(f'Opcode 0x{opcode:03x}({opcode:03d}): {name} (range: {min_val}-{max_val})')
                    return True

            print(f"Param {param} not found in event packets for {name}")
            errors["ArgvNotFound"].append(name)
            return False
        except Exception as e:
            print(f"Error finding event packet for {name}: {e}")
            errors["ArgvNotFound"].append(name)
            return False

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
        
    def read_bytes_at_offset(self, pattern, offset, name):
        addr = find_pattern(pattern)
        
        if addr == idc.BADADDR:
            print(f"ClinetZone {name} pattern not found")
            errors["SigNotFound"].append(name)
            return False
        
        try:
            opcode = ida_bytes.get_dword(addr + offset)
            print(f'Opcode 0x{opcode:03x}({opcode:03d}): {name}')
            
            if name not in self.content:
                self.content[name] = opcode

            return True
        except Exception as e:
            print(f"Error reading memory at {addr + offset}: {e}")
            return False


class SignatureConfig:
    def __init__(self, path=None) -> None:
        self.path = path or os.path.join(ConfigPath, f"signatures.json")

    def load(self):
        with open(self.path, "r") as f:
            return json.load(f)


class SignatureResolver:
    def __init__(self, region) -> None:
        self.region = region
        self._address_cache = {}

    def resolve_config(self, config):
        resolved = copy.deepcopy(config)
        self.resolve_section(resolved["ServerZoneIpcType"])
        self.resolve_section(resolved["ClientZoneIpcType"])
        return resolved

    def resolve_section(self, item):
        for name in item:
            if name == "__init__":
                self.resolve_section(item[name])
            item[name] = self.resolve_entry(item[name], name)

    def resolve_entry(self, sig, name):
        address = idc.BADADDR
        _sig = None

        if type(sig) == str:
            _sig = sig
        elif type(sig) == dict:
            if "Signature" in sig:
                if isinstance(sig["Signature"], dict):
                    if self.region == "Global" and "Global" in sig["Signature"]:
                        _sig = sig["Signature"]["Global"]
                    elif self.region == "CN" and "CN" in sig["Signature"]:
                        _sig = sig["Signature"]["CN"]
                    elif self.region == "KR" and "KR" in sig["Signature"]:
                        _sig = sig["Signature"]["KR"]
                else:
                    _sig = sig["Signature"]

            if _sig is None:
                if self.region == "Global" and "Global" in sig:
                    return self.resolve_entry(sig["Global"], name)
                elif self.region == "CN" and "CN" in sig:
                    return self.resolve_entry(sig["CN"], name)
                elif self.region == "KR" and "KR" in sig:
                    return self.resolve_entry(sig["KR"], name)
            
            if _sig is None:
                return sig

        if not _sig:
            print(f"No valid signature found for {name}")
            errors["SigNotFound"].append(name)
            return None

        address = self.resolve_signature_address(_sig, sig)

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

    def resolve_signature_address(self, pattern, sig):
        index = sig.get("Index", 0) if isinstance(sig, dict) else 0
        times = int(index) + 1 if int(index) else 1
        cache_key = (pattern, times)
        if cache_key not in self._address_cache:
            self._address_cache[cache_key] = find_pattern(pattern, times)
        return self._address_cache[cache_key]


class ConfigReader:
    def __init__(self, config_loader=None, resolver=None) -> None:
        self.config_loader = config_loader or SignatureConfig()
        self.resolver = resolver or SignatureResolver(Region)
        self.raw_content = self.config_loader.load()
        self.content = self.resolver.resolve_config(self.raw_content)


def get_enum_textblock(name, enums, ntype, indent):
    res = [f"public enum {name} : {ntype}", "{"]
    if len(enums) > 0:
        res += [f"    {k} = 0x{enums[k]:04X}," for k in enums]
    else:
        res += ['']
    res += ['};', '']
    return list(map(lambda l: " " * indent + l, res))


def build_opcode_outputs(serverzone, clientzone):
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
    return opcodes, opcodes_internal, debugs


def get_output_paths():
    output_dir = os.path.join(
        OutputPath,
        f"{Region}_{BuildID}",
    )
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    def outpath(name):
        return os.path.join(output_dir, name)

    if Region != "Global":
        ipcs_filename = f"Ipcs_{Region.lower()}.cs"
    else:
        ipcs_filename = "Ipcs.cs"

    return {
        "opcodes_internal": outpath("opcodes_internal.json"),
        "ipcs": outpath(ipcs_filename),
        "errors": outpath("errors.json"),
        "debugs": outpath("debug.json"),
        "opcodes": outpath("opcodes.json"),
        "lemegeton": outpath("lemegeton.xml"),
        "machina": outpath("machina.txt"),
    }


def write_json_outputs(paths, opcodes, opcodes_internal, debugs):
    with open(paths["opcodes"], "w+") as f:
        json.dump(opcodes, f, sort_keys=False, indent=4, separators=(",", ":"))
        print(f"Result saved on {paths['opcodes']}")
    with open(paths["opcodes_internal"], "w+") as f:
        json.dump(opcodes_internal, f, sort_keys=False, indent=4, separators=(",", ":"))
        print(f"Result saved on {paths['opcodes_internal']}")

    with open(paths["errors"], "w+") as f:
        json.dump(errors, f, sort_keys=False, indent=4, separators=(",", ":"))
        print(f"Error saved on {paths['errors']}")
    with open(paths["debugs"], "w+") as f:
        json.dump(debugs, f, sort_keys=False, indent=4, separators=(",", ":"))
        print(f"Dump saved on {paths['debugs']}")


def write_machina(paths, opcodes):
    template_path = os.path.join(ConfigPath, f"machina.template")
    mresult = []
    with open(template_path, "r") as f:
        mtemplate = f.readlines()
    for l in mtemplate:
        match = re.match(r".+(?P<opcode_name>\{.+\})", l)
        if not match:
            mresult.append(l)
            continue
        opcode_temp = match.groupdict()["opcode_name"]
        opcode_name = opcode_temp[1:-1]
        for op in (
            opcodes["lists"]["ServerZoneIpcType"] + opcodes["lists"]["ClientZoneIpcType"]
        ):
            if op["name"] == opcode_name:
                l = l.replace(opcode_temp, f"{op['opcode']:X}")
                break
        mresult.append(l)
    with open(paths["machina"], "w+") as f:
        f.writelines(mresult)
    print(f'Gen machina.txt on {paths["machina"]}')


def write_ipcs(paths, serverzone, clientzone):
    ipcs_line = [
        "// Generated by https://github.com/gamous/FFXIVNetworkOpcodes",
        f"namespace FFXIVOpcodes.{Region}",
        "{",
    ]
    ipcs_line += get_enum_textblock("ServerLobbyIpcType", {}, 'ushort', 4)
    ipcs_line += get_enum_textblock("ClientLobbyIpcType", {}, 'ushort', 4)
    ipcs_line += get_enum_textblock("ServerZoneIpcType", serverzone.content, 'ushort', 4)
    ipcs_line += get_enum_textblock("ClientZoneIpcType", clientzone.content, 'ushort', 4)
    ipcs_line += get_enum_textblock("ServerChatIpcType", {}, 'ushort', 4)
    ipcs_line += get_enum_textblock("ClientChatIpcType", {}, 'ushort', 4)
    ipcs_line += ["}"]
    ipcs_line = list(map(lambda l: l + "\n", ipcs_line))
    with open(paths["ipcs"], "w+") as f:
        f.writelines(ipcs_line)
    print(f'Gen ipcs on {paths["ipcs"],}')


def write_lemegeton(paths, serverzone):
    Region_Name="EN/DE/FR/JP" if Region=="Global" else Region

    lemegeton_opcodes=f"""		<Region Name="{Region_Name}" Version="{BuildID}.0000.0000">
			<Opcodes>
				<Opcode Name="StatusEffectList" Id="{serverzone.content["StatusEffectList"]}" />
				<Opcode Name="StatusEffectList2" Id="{serverzone.content["StatusEffectList2"]}" />
				<Opcode Name="StatusEffectList3" Id="{serverzone.content["StatusEffectList3"]}" />
				<Opcode Name="Ability1" Id="{serverzone.content["Effect"]}" />
				<Opcode Name="Ability8" Id="{serverzone.content["AoeEffect8"]}" />
				<Opcode Name="Ability16" Id="{serverzone.content["AoeEffect16"]}" />
				<Opcode Name="Ability24" Id="{serverzone.content["AoeEffect24"]}" />
				<Opcode Name="Ability32" Id="{serverzone.content["AoeEffect32"]}" />
				<Opcode Name="ActorCast" Id="{serverzone.content["ActorCast"]}" />
				<Opcode Name="EffectResult" Id="{serverzone.content["EffectResult"]}" />
				<Opcode Name="ActorControl" Id="{serverzone.content["ActorControl"]}" />
				<Opcode Name="ActorControlSelf" Id="{serverzone.content["ActorControlSelf"]}" />
				<Opcode Name="ActorControlTarget" Id="{serverzone.content["ActorControlTarget"]}" />
				<Opcode Name="MapEffect" Id="{serverzone.content["MapEffect"]}" />
				<Opcode Name="EventPlay" Id="{serverzone.content["EventPlay"]}" />
				<Opcode Name="EventPlay64" Id="{serverzone.content["EventPlay64"]}" />
			</Opcodes>
		</Region>"""
    with open(paths["lemegeton"], "w+") as f:
        f.write(lemegeton_opcodes)
    print(f'Gen lemegeton_bludprint.xml on {paths["lemegeton"],}')


def main():
    config = ConfigReader()
    print(config.content)
    serverzone = ServerZoneIpcType(config)
    print(serverzone.content)
    clientzone = ClientZoneIpcType(config)
    print(clientzone.content)
    print(errors)

    opcodes, opcodes_internal, debugs = build_opcode_outputs(serverzone, clientzone)
    paths = get_output_paths()
    write_json_outputs(paths, opcodes, opcodes_internal, debugs)
    write_machina(paths, opcodes)
    write_ipcs(paths, serverzone, clientzone)
    write_lemegeton(paths, serverzone)


if __name__ == "__main__":
    main()
