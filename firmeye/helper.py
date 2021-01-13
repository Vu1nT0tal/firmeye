# -*- coding: utf-8 -*-

import ida_name
import ida_segment
import ida_funcs
import ida_gdl
import ida_idaapi
import ida_ua
import ida_bytes
import idautils
import idc


def num_to_hexstr(num):
    return format(num, '#010x')

def is_func_call(ea):
    """
    判读是否是一个函数调用指令
    """

    op1 = idc.print_operand(ea, 0)
    for func_addr in idautils.Functions():
        func_name = ida_funcs.get_func_name(func_addr)
        if op1 == func_name:
            return True
        else:
            continue
    return False

def rename_func(ea, funcname):
    """
    函数名重命名（如有重名在末尾加数字区分）
    """

    currname = funcname
    count = 1
    if ea == None:
        print("Error: can't rename Nonetype to %s" % funcname)
        return False
    while not ida_name.set_name(ea, currname, ida_name.SN_CHECK):
        currname = "%s_%d" % (funcname, count)
        count += 1
        if count > 100:
            print("Error: rename_func looped too much for 0x%d -> %s" % (ea, funcname))
            return False
    return True

def unname_func(ea):
    """
    取消函数命名，退回sub_xxxx
    """

    if not ida_name.set_name(ea, "", ida_name.SN_CHECK):
        print("Error: unname_func: could not remove name for element")
        return False
    return True

def get_segments():
    """
    返回所有segment的名字列表
    """

    seg_names = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        seg_names.append(ida_segment.get_segm_name(seg))
    return seg_names

def name_to_addr(s):
    """
    返回任意名称的地址：function, label, global...
    """

    addr = ida_name.get_name_ea(ida_idaapi.BADADDR, s)
    if addr == ida_idaapi.BADADDR:
        print("Error: name_to_addr: Failed to find '%s' symbol" % s)
        return None
    return addr

def addr_to_name(ea):
    """
    返回任意地址的名称
    """
    name = ida_name.get_name(ea, ida_name.GN_VISIBLE)
    if name == "":
        print("Error: addr_to_name: Failed to find '0x%x' address" % ea)
        return ""
    return name

def get_call_args_arm(ea, count_max=10):
    """
    获得函数调用参数（当前仅支持4个参数）
    """

    args = {}

    mnem = ida_ua.ua_mnem(ea)
    if mnem != "BL" and mnem != "SVC" and mnem != "BLNE" and mnem != "BLHI" and mnem != "BLEQ":
        print("Error: not a BL or SVC or BLNE or BLHI or BLEQ instruction at 0x%x" % ea)
        return None

    arg_inst_arm_mov = ["MOV     R0,",
                        "MOV     R1,",
                        "MOV     R2,",
                        "MOV     R3,"]
    arg_inst_arm_adr = ["ADR     R0,",
                        "ADR     R1,",
                        "ADR     R2,",
                        "ADR     R3,"]
    arg_inst_arm_ldr = ["LDR     R0,",
                        "LDR     R1,",
                        "LDR     R2,",
                        "LDR     R3,"]
    arg_inst_arm_adr2 = ["ADREQ   R0,",
                         "ADREQ   R1,",
                         "ADDEQ   R2,",
                         "ADREQ   R3,"]
    arg_inst_arm_mov2 = ["MOVEQ   R0,",
                         "MOVEQ   R1,",
                         "MOVEQ   R2,",
                         "MOVEQ   R3,"]
    arg_inst_arm_adr3 = ["ADRNE   R0,",
                         "ADRNE   R1,",
                         "ADDNE   R2,",
                         "ADRNE   R3,"]

    ea = ida_bytes.prev_head(ea, 0)
    count = 0
    while count <= count_max:
        disasm_line = idc.generate_disasm_line(ea, 0)
        for i in range(len(arg_inst_arm_mov)):
            #print("'%s'" % arg_inst_arm_mov[i])
            # 假设最接近调用的指令是赋值指令，忽略其他情况（如碰到另一个MOV reg）
            inst_list = [arg_inst_arm_mov[i],
                         arg_inst_arm_mov2[i],
                         arg_inst_arm_adr[i],
                         arg_inst_arm_adr2[i],
                         arg_inst_arm_adr3[i]]
            if any(inst in disasm_line for inst in inst_list):
                if i not in args.keys():
                    args[i] = idc.get_operand_value(ea, 1)
                    print("Found argument %d: 0x%x" % (i, args[i]))
            elif arg_inst_arm_ldr[i] in disasm_line:
                if i not in args.keys():
                    addr = idc.get_operand_value(ea, 1)
                    args[i] = ida_bytes.get_wide_dword(addr)
                    print("Found argument %d: 0x%x" % (i, args[i]))
        ea = ida_bytes.prev_head(ea, 0)
        count += 1
    return args

def find_ret_block(addr):
    """
    寻找函数返回块，不支持多返回函数
    """

    func = ida_funcs.get_func(addr)
    f = ida_gdl.FlowChart(func)
    for block in f:
        if ida_gdl.is_ret_block(block.type):
            return block
    return None

def function_count_instructions(ea):
    """
    返回函数的指令数量
    """
    E = list(idautils.FuncItems(ea))
    return len(E)
