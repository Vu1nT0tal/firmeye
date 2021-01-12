# -*- coding: utf-8 -*-

import re
import idc
import ida_bytes
import ida_ua
import ida_funcs
import ida_nalt
import ida_gdl
import ida_xref
import ida_segment
import ida_idaapi
import idautils

from firmeye.config import SINK_FUNC, INST_LIST
from firmeye.logger import FirmEyeLogger
from firmeye.helper import num_to_hexstr


class FirmEyeSinkFuncMgr():
    """sink函数管理器
    提供获取sink函数的调用地址和交叉引用信息的工具函数
    sink_func_info: 默认存储sink函数全局配置信息
    """

    def __init__(self, sink_func_info=SINK_FUNC):
        self.sink_func_info = sink_func_info
    
    def gen_sink_func_addr(self):
        for func_addr in idautils.Functions():
            func_name = ida_funcs.get_func_name(func_addr)
            if self.sink_func_info.has_key(func_name):
                yield (func_name, func_addr)
            else:
                continue
    
    def gen_func_xref(self, func_addr):
        for xref_addr in idautils.CodeRefsTo(func_addr, 0):
            if ida_funcs.get_func(xref_addr):
                yield xref_addr
            else:
                continue
    
    def get_func_xref(self, func_addr):
        return [xref_addr for xref_addr in self.gen_func_xref(func_addr)]
    
    def gen_sink_func_xref(self):
        for func_name, func_addr in self.gen_sink_func_addr():
            yield (func_name, self.get_func_xref(func_addr))
    
    def get_one_func_xref(self, func_name):
        for func_addr in idautils.Functions():
            func_name_t = ida_funcs.get_func_name(func_addr)
            if func_name == func_name_t:
                return self.get_func_xref(func_addr)
            else:
                continue


class FirmEyeArgsTracer():
    """参数回溯器
    基于DFS提供寄存器回溯功能
    addr: 回溯起始地址
    reg: 回溯寄存器
    max_node: 最大回溯节点数
    """

    def __init__(self, addr, reg, max_node=1024):
        self.trace_addr = addr
        self.trace_reg = reg

        self.init_tree()
        self.init_cache()
        self.init_blk_cfg()

        self.max_node = max_node

    def init_blk_cfg(self):
        """
        初始化基本块CFG
        """
        func_t = ida_funcs.get_func(self.trace_addr)
        if func_t:
            self.cfg = ida_gdl.FlowChart(func_t)
        else:
            self.cfg = []

    def get_blk(self, addr):
        """
        获取addr所在的基本块
        """
        for blk in self.cfg:
            if blk.startEA <= addr and addr < blk.endEA:
                return blk
        return None
    
    def create_tree_node(self, addr, prev=None):
        """
        创建树节点
        """
        return {
            'addr': addr,
            'prev': prev,
        }
    
    def init_tree(self):
        """
        初始化回溯树
        """
        self.tree = self.create_tree_node(self.trace_addr)
    
    def push_cache_node(self, addr, key):
        """
        将节点地址添加到缓存列表
        """
        if self.cache.has_key(key):
            self.cache['all_node'].add(addr)
            if addr not in self.cache[key]:
                self.cache[key].add(addr)
                return True
        return False
    
    def init_cache(self):
        """
        初始化缓存列表，记录回溯过程中经过的节点地址
        """
        self.cache = {'addr': set(), 'all_node': set()}
        for r in ['R'+str(i) for i in range(16)]:
            self.cache.update({r: set()})
    
    def parse_operands(self, mnem, tar_addr):
        """
        提取块拷贝指令（LDM/STM）涉及的寄存器
        # TODO 有待改进
        """

        regs = []
        if mnem.startswith('LDM') or mnem.startswith('STM'):
            op2 = idc.print_operand(tar_addr, 1).strip('{}')
            for item in op2.split(','):
                if '-' in item:
                    [a, b] = re.findall(r"\d+\.?\d*", item)
                    a, b = int(a), int(b)
                    for i in range(b - a + 1):
                        regs.append("R" + str(a + i))
                else:
                    regs.append(item)

        if mnem.startswith('LDR') or mnem.startswith('STR') or mnem.startswith('VLDR'):
            op2 = idc.print_operand(tar_addr, 1).strip('[]')
            for item in op2.split(','):
                item = item.strip('[]')
                if 'R' in item or 'SP' in item:
                    regs.append(item)

        return regs

    def get_next_reg(self, addr, reg):
        """
        寻找下一个赋值来源寄存器
        返回寄存器名或None
        """

        reg_t = reg
        addr_t = addr

        mnemonic_t = ida_ua.print_insn_mnem(addr_t)
        line = idc.generate_disasm_line(addr_t, 0)
        if reg_t == 'R0' and mnemonic_t.startswith('BLX') and addr_t != self.trace_addr:
            FirmEyeLogger.info("找到赋值点\t"+num_to_hexstr(addr)+"\t"+line)
            return None

        inst_list_t = INST_LIST
        reg_re = re.compile(reg_t + '\\D|' + reg_t + '\\Z')
        if reg_re.search(line):
            if mnemonic_t in reduce(lambda x, y: x + y, [value for value in inst_list_t.values()]):
                op1 = idc.print_operand(addr_t, 0).split("!")[0]
                if mnemonic_t in inst_list_t['load_multi']:
                    # 找到      LDM R1, {R0-R3}
                    regs = self.parse_operands(mnemonic_t, addr_t)
                    if reg_t not in regs:
                        FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                    else:
                        FirmEyeLogger.info("找到赋值点\t"+num_to_hexstr(addr)+"\t"+line)
                        return None
                else:
                    if op1 != reg_t or mnemonic_t in inst_list_t['other']:
                        FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                    elif mnemonic_t in inst_list_t['arithmetic']:
                        # 停止      ADD R0, SP; ADD R0, SP, #10
                        # 回溯R0    ADD R0, R1; ADD R0, #10
                        # 回溯R1    ADD R0, R1, #10; ADD R0, R1, R2
                        op2_tmp = idc.print_operand(addr_t, 1)
                        if idc.get_operand_type(addr_t, 2) == ida_ua.o_void:
                            if idc.get_operand_type(addr_t, 1) == ida_ua.o_reg:
                                if op2_tmp == 'SP':
                                    FirmEyeLogger.info("取消回溯SP\t"+num_to_hexstr(addr)+"\t"+line)
                                    return None
                                else:
                                    FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                            else:
                                FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                        elif idc.get_operand_type(addr_t, 3) == ida_ua.o_void:
                            op3_tmp = idc.print_operand(addr_t, 2)
                            if op2_tmp == 'SP' or op3_tmp == 'SP':
                                FirmEyeLogger.info("取消回溯SP\t"+num_to_hexstr(addr)+"\t"+line)
                                return None
                            elif reg_t == op2_tmp or reg_t == op3_tmp:
                                FirmEyeLogger.info("复杂运算\t"+num_to_hexstr(addr)+"\t"+line)
                                return None
                            else:
                                reg_t = op2_tmp
                                FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                        else:
                            op3_tmp = idc.print_operand(addr_t, 2)
                            op4_tmp = idc.print_operand(addr_t, 3)
                            if op2_tmp == 'SP' or op3_tmp == 'SP' or op4_tmp == 'SP':
                                FirmEyeLogger.info("取消回溯SP\t"+num_to_hexstr(addr)+"\t"+line)
                                return None
                            elif reg_t == op2_tmp or reg_t == op3_tmp or reg_t == op4_tmp:
                                FirmEyeLogger.info("复杂运算\t"+num_to_hexstr(addr)+"\t"+line)
                                return None
                            else:
                                reg_t = op2_tmp
                                FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                    elif mnemonic_t in inst_list_t['move']:
                        # 停止      MOV R0, SP; MOV R0, SP, #10
                        # 找到      MOV R0, #10
                        # 回溯R1    MOV R0, R1
                        # 回溯D8    VMOV R0, R1, D16
                        if mnemonic_t.startswith('VMOV'):
                            op3_tmp = idc.print_operand(addr_t, 2)
                            reg_t = op3_tmp
                            FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                        else:
                            op2_tmp = ida_ua.print_operand(addr_t, 1)
                            if op2_tmp == 'SP':
                                FirmEyeLogger.info("取消回溯SP\t"+num_to_hexstr(addr)+"\t"+line)
                                return None
                            elif idc.get_operand_type(addr_t, 1) == ida_ua.o_reg:
                                reg_t = op2_tmp
                                FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                            elif mnemonic_t in ['MOVT.W', 'MOVTGT.W', 'MOVTLE.W']:
                                FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                            else:
                                FirmEyeLogger.info("找到赋值点\t"+num_to_hexstr(addr)+"\t"+line)
                                return None
                    elif mnemonic_t in inst_list_t['load']:
                        # 找到      LDR R0, =xxxxxxx
                        # 停止      LDR R0, [SP, #10]
                        # 回溯R1    LDR R0, [R1, #10]
                        # 回溯R0    LDR R0, [R0, R1, #10]
                        if idc.get_operand_type(addr_t, 1) == ida_ua.o_mem:
                            FirmEyeLogger.info("找到赋值点\t"+num_to_hexstr(addr)+"\t"+line)
                            return None
                        else:
                            regs_tmp = self.parse_operands(mnemonic_t, addr_t)
                            if 'SP' in regs_tmp:
                                FirmEyeLogger.info("取消回溯SP\t"+num_to_hexstr(addr)+"\t"+line)
                                return None
                            elif reg_t in regs_tmp:
                                FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                            else:
                                reg_t = regs_tmp[0]
                                FirmEyeLogger.info("回溯"+reg_t+"\t"+num_to_hexstr(addr)+"\t"+line)
                    else:
                        FirmEyeLogger.info("未知指令\t"+num_to_hexstr(addr)+"\t"+line)
            else:
                FirmEyeLogger.info("未知指令\t"+num_to_hexstr(addr)+"\t"+line)
        else:
            pass

        return reg_t

    def get_all_ref(self, addr):
        """
        获取所有引用到addr的地址
        """
        xref_t = []
        addr_t = ida_xref.get_first_cref_to(addr)
        while addr_t != ida_idaapi.BADADDR:
            xref_t.append(addr_t)
            addr_t = ida_xref.get_next_cref_to(addr, addr_t)
        return xref_t
    
    def get_node_nums(self):
        """
        获取已回溯节点数
        """
        return len(self.cache['all_node'])
    
    def set_color(self, addr, color_type):
        """
        设置指令背景色
        """
        ida_nalt.set_item_color(addr, color_type)
    
    def trace_handle(self, addr, reg):
        """
        处理回溯事件
        """
        next_addr = ida_bytes.prev_head(addr, 0)
        next_reg = self.get_next_reg(addr, reg)

        return (next_addr, next_reg)

    def trace_block(self, blk, node, reg):
        """
        在一个基本块内回溯
        """
        reg_t = reg
        cur_t = node['addr']
        while reg_t and cur_t >= blk.startEA:
            cur_t, reg_t = self.trace_handle(cur_t, reg_t)

        return (ida_bytes.next_head(cur_t, ida_idaapi.BADADDR), reg_t)

    def trace_next(self, blk, node, reg):
        """
        下一轮回溯
        """
        for ref_addr in self.get_all_ref(blk.startEA):
            block = self.get_blk(ref_addr)
            if block:
                FirmEyeLogger.info("基本块跳转\t"+num_to_hexstr(ref_addr)+"\t"+idc.generate_disasm_line(ref_addr, 0))
                node_t = self.create_tree_node(ref_addr, prev=node)
                self.dfs(node_t, reg, block)
    
    def dfs(self, node, reg, blk):
        """深度优先搜索
        node: 当前节点
        reg: 回溯寄存器
        blk: 当前基本块
        """
        blk_t = blk
        if self.get_node_nums() < self.max_node:    # 避免路径爆炸
            if self.push_cache_node(node['addr'], reg): # 避免重复，加快速度
                cur_t, reg_t = self.trace_block(blk_t, node, reg)
                if reg_t:
                    # 如果返回一个新的寄存器，开启下一轮回溯
                    self.trace_next(blk_t, node, reg_t)
                else:
                    self.cache['addr'].add(cur_t)
            else:
                FirmEyeLogger.info("该块已经回溯，取消操作")
        else:
            FirmEyeLogger.info("超出最大回溯块数量")
    
    @FirmEyeLogger.show_time_cost
    @FirmEyeLogger.log_time
    def run(self):
        """
        启动回溯
        """
        trace_blk = self.get_blk(self.trace_addr)
        self.dfs(self.tree, self.trace_reg, trace_blk)
        return list(self.cache['addr'])


class FirmEyeStrMgr():
    """字符串管理器
    提供获取和解析字符串的功能
    minl: 定义字符串的最短长度
    """

    strings = {}    # 管理器初始化时进行缓存

    def __init__(self, minl=1):
        st_obj = idautils.Strings()
        st_obj.setup(minlen=minl)
        for string in st_obj:
            self.strings[string.ea] = str(string)
    
    @classmethod
    def get_string_from_mem(cls, addr):
        """
        从addr逐字节获取字符
        """

        string = ''
        chr_t = ida_bytes.get_wide_byte(addr)
        i = 0
        while chr_t != 0:
            chr_t = ida_bytes.get_wide_byte(addr+i)
            string += chr(chr_t)
            i += 1
        return string[:-1]

    @classmethod
    def get_mem_string(cls, addr):
        """
        获取内存中的字符串
        """

        addr_t = addr
        dref = idautils.DataRefsFrom(addr_t)
        strs = [cls.strings[x] for x in dref if cls.strings.has_key(x)]

        # 处理几种特殊情况
        # LDR R1, =sub_xxxx
        # LDR R1, =loc_xxxx
        if idc.print_operand(addr, 1)[:5] in ['=sub_', '=loc_']:
            return []
        
        # LDR R1, =unk_53B4B6
        # .rodata:0053B4B6 http:
        # .rodata:0053B4BB //%s%s
        if strs != [] and strs[0].find('%') == -1:
            strs = []
            dref = idautils.DataRefsFrom(addr_t)
            for x in dref:
                segname = ida_segment.get_segm_name(ida_segment.getseg(x))
                if segname not in ['.text', '.bss']:
                    strs.append(cls.get_string_from_mem(x))
        
        # LDR R1, =(aFailedToGetAnI+0x22)
        # LDR R2, =(aSS - 0xCFA4)
        # ADD R2, PC, R2
        if strs == []:
            dref = idautils.DataRefsFrom(addr_t)
            for x in dref:
                segname = ida_segment.get_segm_name(ida_segment.getseg(x))
                if segname not in ['.text', '.bss']:
                    strs.append(cls.get_string_from_mem(x))
                elif len(list(idautils.DataRefsFrom(x))) == 0:
                    reg_t = idc.print_operand(addr_t, 0)
                    num1 = ida_bytes.get_wide_dword(x)
                    while ida_ua.print_insn_mnem(addr_t) != 'ADD' or (idc.print_operand(addr_t, 0) != reg_t and idc.print_operand(addr_t, 1) != 'PC'):
                        addr_t = ida_bytes.next_head(addr_t, ida_idaapi.BADADDR)
                    num2 = addr_t + 8
                    addr_t = num1 + num2
                    strs.append(cls.get_string_from_mem(addr_t))
        
        # MOVW R1, #0x87B4
        # MOVT.W R1, #0x52
        if strs == [] and ida_ua.print_insn_mnem(addr_t) == 'MOVW':
            reg_t = idc.print_operand(addr_t, 0)
            num1 = int(idc.print_operand(addr_t, 1).split('#')[1], 16)
            while ida_ua.print_insn_mnem(addr_t) not in ['MOVTGT.W', 'MOVTLE.W', 'MOVT.W'] or idc.print_operand(addr_t, 0) != reg_t:
                addr_t = ida_bytes.next_head(addr_t, ida_idaapi.BADADDR)
            num2 = int(idc.print_operand(addr_t, 1).split('#')[1], 16)
            addr_t = (num2<<16) + num1
            strs.append(cls.get_string_from_mem(addr_t))
        
        return strs

    @classmethod
    def parse_format_string(cls, string):
        """
        解析格式字符串
        %[parameter][flags][field width][.precision][length]type
        """

        _type = ['d', 'i', 'u', 'f', 'F', 'e', 'E', 'g', 'G', 'x', 'X', 'o', 's', 'c', 'p', 'a', 'A', 'n']
        pattern = '.*?[%s]' % ''.join(_type)
        fmt_list = string.split("%")[1:]
        results = []
        for fmt in fmt_list:
            re_obj = re.search(pattern, fmt)
            if re_obj:
                results.append(re_obj.group())
        return results
