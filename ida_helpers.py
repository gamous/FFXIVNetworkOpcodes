import bisect
import typing

import ida_gdl
import ida_ua
import ida_xref
import idautils
import idc


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


class CallGraphCache:
    def __init__(self, target_resolver):
        self._target_resolver = target_resolver
        self._call_targets = {}
        self._call_xrefs_to = {}

    def call_xrefs_to(self, ea):
        if ea not in self._call_xrefs_to:
            self._call_xrefs_to[ea] = [
                xref
                for xref in idautils.XrefsTo(ea)
                if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF)
            ]
        return self._call_xrefs_to[ea]

    def call_targets_from(self, func_start_ea):
        if func_start_ea not in self._call_targets:
            targets = set()
            for item_ea in idautils.FuncItems(func_start_ea):
                if idc.print_insn_mnem(item_ea) == "call":
                    target = self._target_resolver(item_ea)
                    if target != idc.BADADDR:
                        targets.add(target)
            self._call_targets[func_start_ea] = targets
        return self._call_targets[func_start_ea]


class FunctionView:
    def __init__(self, func):
        self.func = func
        self.blocks = list(ida_gdl.FlowChart(func))
        self.block_by_start = {block.start_ea: block for block in self.blocks}
        self.addr_to_block = {}
        self.insns_by_block = {}
        self._decoded = {}
        self._last_insn = {}
        for block in self.blocks:
            insns = []
            ea = block.start_ea
            while ea != idc.BADADDR and ea < block.end_ea:
                self.addr_to_block[ea] = block
                insns.append(ea)
                ea = idc.next_head(ea, block.end_ea)
            self.insns_by_block[block.start_ea] = insns

    def block_at(self, ea):
        return self.addr_to_block.get(ea)

    def block_starting_at(self, ea):
        return self.block_by_start.get(ea)

    def contains_block(self, ea):
        return ea in self.block_by_start

    def block_insns(self, block):
        return self.insns_by_block.get(block.start_ea, [])

    def last_insn(self, block):
        if block.start_ea not in self._last_insn:
            insns = self.block_insns(block)
            self._last_insn[block.start_ea] = insns[-1] if insns else idc.BADADDR
        return self._last_insn[block.start_ea]

    def decode(self, ea):
        if ea not in self._decoded:
            insn = ida_ua.insn_t()
            self._decoded[ea] = insn if ida_ua.decode_insn(insn, ea) > 0 else None
        return self._decoded[ea]


class RangeIndex:
    def __init__(self, ranges):
        self._items = sorted(
            ((item["start"], item["end"], item["case"]) for item in ranges),
            key=lambda item: item[0],
        )
        self._starts = [item[0] for item in self._items]
        self._max_width = max((end - start for start, end, _ in self._items), default=0)

    def index(self, ea):
        cases = set()
        idx = bisect.bisect_right(self._starts, ea) - 1
        while idx >= 0:
            start, end, case = self._items[idx]
            if start <= ea < end:
                cases.add(case)
            if ea - start > self._max_width:
                break
            idx -= 1
        return sorted(cases)
