#credit: ny
from idc import *
from idaapi import *
from idautils import *

min_ea = inf_get_min_ea()
max_ea = inf_get_max_ea()


def line_sig(ea, mask_op=None):
    insn = ida_ua.insn_t()
    decode_insn(insn, ea)
    line_bytes = list(get_bytes(ea, insn.size))
    for op in insn.ops:
        if not op.type: break
        if mask_op is None or op.type not in mask_op:
            offset = max(op.offb, 1)
            line_bytes[offset:] = [-1] * (insn.size - offset)
            break
    return "".join(f'{b:02x} ' if b > -1 else '? ' for b in line_bytes)


def sig_search(sig: str, max_search_cnt: int = 10):
    addr = min_ea
    while max_search_cnt > 0:
        addr = find_binary(addr, max_ea, sig, 16, SEARCH_DOWN | SEARCH_NEXT)
        if addr == BADADDR: break
        yield addr
        max_search_cnt -= 1


def find_xrefs(ea: int) -> dict:
    xrefs = {}
    for xref in XrefsTo(ea, 0):
        xrefs.setdefault(xref.type, []).append(xref.frm)
    return xrefs


def is_only_ref_from(from_, to):
    found = False
    for xref in XrefsTo(to, 0):
        if xref.type in (ida_xref.fl_JF, ida_xref.fl_JN, ida_xref.fl_F):
            if xref.frm != from_:
                return False
            else:
                found = True
    return found


def is_only_ref_to(from_, to):
    found = False
    for xref in XrefsFrom(from_, 0):
        if xref.type in (ida_xref.fl_CF, ida_xref.fl_CN, ida_xref.fl_JF, ida_xref.fl_JN):
            if xref.frm != to:
                return False
            else:
                found = True
    return found


def compete_find_sig(eas: list, select_cnt: int = 10, max_inst: int = 10):
    search_data = {ea: {'ea': ea, 'sig': '', 'end': idc.find_func_end(ea)} for ea in eas}
    rtn_cnt = 0
    for _i in range(max_inst):
        for raw_ea, data in list(search_data.items()):
            try:
                sig = data['sig'] = data['sig'] + line_sig(data['ea'])
            except Exception as e:
                print(f"[!]make sig error at {raw_ea:x} - {data['ea']:x}: {e}")
                print(traceback.format_exc())
                del search_data[raw_ea]
                continue
            cnt = 99
            if _i:
                cnt = len(list(sig_search(sig)))
                if cnt == 1:
                    yield 1, raw_ea, sig
                    rtn_cnt += 1
                    if rtn_cnt == select_cnt: return
                    del search_data[raw_ea]
                    continue
                if cnt < 0:
                    print(f"[!]none match at {raw_ea:x} to {data['ea']} with sig {sig}")
                    del search_data[raw_ea]
                    continue
            next_ea = next_head(data['ea'], data['end'])
            if next_ea == BADADDR or not is_only_ref_from(data['ea'], next_ea):
                yield cnt, raw_ea, sig
                del search_data[raw_ea]
                continue
            data['ea'] = next_ea
    for raw_ea, data in list(search_data.items()):
        sig = data['sig']
        yield len(list(sig_search(sig))), raw_ea, sig


def get(ea):
    print(f'[+]start finding sig for {ea:x} ({idc.get_name(ea,GN_DEMANGLED)})')
    _eas = [ea] if get_func(ea) else []
    for ref_t, xref in find_xrefs(ea).items():
        if ref_t != fl_F:
            _eas.extend(_ea for _ea in xref if get_func(_ea))
    print(f'[+]{len(_eas)} ea search')
    res = sorted(compete_find_sig(_eas, 5, 20))
    min_match = res[0][0]
    if min_match != 1:
        print(f"[!]cant find unique sig, print sig match {min_match}...")
    sig: str
    found = []
    for match, raw_ea, sig in res:
        if match != min_match: break
        if min_match != 1:
            while True:
                short_sig = sig[:sig.rindex('?')].rstrip(' ?')
                if len(list(sig_search(short_sig, min_match + 1))) == min_match:
                    sig = short_sig
                else:
                    break
        sub_sig = ''
        if raw_ea != ea:
            insn = ida_ua.insn_t()
            decode_insn(insn, raw_ea)
            i = 0
            _insn = iter(insn.ops)
            while True:
                try:
                    op = next(_insn)
                except StopIteration:
                    break
                if not op.type:
                    break
                if get_operand_value(raw_ea, i) == ea:
                    offset = max(op.offb, 1)
                    try:
                        n_op = next(_insn)
                        if not n_op.type: raise StopIteration
                        next_offset = n_op.offb or insn.size
                    except (AttributeError, StopIteration):
                        next_offset = insn.size
                    _sig = sig.split(' ')
                    _sig[offset:next_offset] = ['*'] * (next_offset - offset)
                    # sub_sig = sig
                    sig = ' '.join(_sig)
                    break
        sig = sig.rstrip(' ?')
        print(f'[+] {raw_ea:x} : {sig}')
        found.append(sig)
        # if sub_sig: print(f'[...] {raw_ea:x} : {sub_sig}')
    print(f'[*]done')
    return min_match, found


if __name__ == '__main__':
    choice=ask_buttons('current', 'value', '', 1, 'sig to make')
    if choice==1:
        get(here())
    elif choice==2:
        for i in range(2):
            if max_ea > (v := get_operand_value(here(), i)) > min_ea:
                get(v)
                break
    print(f'[+] done')
