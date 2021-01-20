# -*- coding: utf-8 -*-

import os
import csv
import random
from functools import reduce

import idc
import idautils
import ida_kernwin
import ida_nalt
import ida_dbg
import ida_ua
import ida_funcs
import ida_bytes
import ida_idaapi

from firmeye.config import SINK_FUNC, FUNC_TAG
from firmeye.utility import FEArgsTracer, FEStrMgr, FESinkFuncMgr
from firmeye.helper import num_to_hexstr
from firmeye.view.chooser import AnalysisChooser, AnalysisChooseData
from firmeye.logger import FELogger

CUSTOM_FUNC = {}   # 全局变量，保存用户临时定义的sink函数

def get_custom_func():
    """返回临时函数集合"""
    return CUSTOM_FUNC

def printf_func_analysis(func_name, xref_list):
    """
    printf系列函数漏洞分析
    """

    def check_fmt_reg(xref_addr_t, fmt_reg, vuln_regs, siz_addr_t=0, parse=False):
        vuln_flag = 0
        addr1 = 0
        str1 = ''

        if siz_addr_t == 0:
            str_siz_addr = ''
        else:
            str_siz_addr = num_to_hexstr(siz_addr_t)

        FELogger.info("从%s回溯格式字符串%s" % (num_to_hexstr(xref_addr_t), fmt_reg))
        tracer = FEArgsTracer(xref_addr_t, fmt_reg)
        source_addr = tracer.run()
        print('source_addr: ', source_addr)
        # 判断是否找到字符串来源地址
        if source_addr == []:
            FELogger.info("未找到目标地址%s" % num_to_hexstr(xref_addr_t))
            vuln_flag = 1
        else:
            for fmt_addr in source_addr:
                addr1 = fmt_addr
                fmt_str = FEStrMgr.get_mem_string(fmt_addr)
                # 判断是否找到字符串
                if fmt_str == []:
                    FELogger.info('格式字符串未找到%s' % num_to_hexstr(xref_addr_t))
                    vuln_flag = 1
                    str1 = ''
                else:
                    FELogger.info('找到格式字符串%s' % num_to_hexstr(xref_addr_t))
                    str1 = fmt_str[0]
                    if parse == False:
                        vuln_flag = 0
                    else:
                        fmt_list = FEStrMgr.parse_format_string(str1)
                        # 判断字符串中的格式字符
                        if fmt_list != [] and 's' in ''.join(fmt_list):
                            if vuln_regs[-1] == '...':
                                args_num = len(fmt_list) + len(vuln_regs) - 1
                                if args_num > 4:
                                    fmt_list = fmt_list[:(4 - (len(vuln_regs) - 1))]

                                for idx in range(len(fmt_list)):
                                    if 's' in fmt_list[idx]:
                                        str_reg = 'R%s' % (len(vuln_regs)-1 + idx)
                                        FELogger.info("从%s回溯字符串%s" % (num_to_hexstr(xref_addr_t), str_reg))
                                        str_tracer = FEArgsTracer(xref_addr_t, str_reg, max_node=256)
                                        str_source_addr = str_tracer.run()
                                        print('str_source_addr: ', str_source_addr)
                                        if str_source_addr == []:
                                            FELogger.info("未找到%s字符串地址" % str_reg)
                                            vuln_flag = 1
                                            break
                                        else:
                                            for str_addr in str_source_addr:
                                                if idc.get_operand_type(str_addr, 1) == ida_ua.o_mem:
                                                    vuln_flag = 0
                                                else:
                                                    vuln_flag = 1
                                                    break
                                    else:
                                        continue
                            else:
                                vuln_flag = 1
                        else:
                            FELogger.info("格式字符串不包含s转换符号")
                            vuln_flag = 0

        data = AnalysisChooseData(vuln=vuln_flag, name=func_name_t, ea=xref_addr_t, addr1=addr1, str1=str1, other1=str_siz_addr)
        items.append(data)

    func_name_t = func_name
    xref_list_t = xref_list
    items = []
    vuln_rule = SINK_FUNC[func_name_t]['vuln_rule']
    args_rule = SINK_FUNC[func_name_t]['args_rule']
    for xref_addr_t in xref_list_t:
        for rule in vuln_rule:
            FELogger.info('检测%s漏洞' % rule['vuln_type'])

            if rule['vuln_type'] == 'format_string':
                fmt_reg = rule['vuln_regs'][0]
                check_fmt_reg(xref_addr_t, fmt_reg, args_rule, parse=False)
            else:
                vuln_regs = rule['vuln_regs']
                if vuln_regs[-1] == '...':
                    fmt_reg = vuln_regs[-2]
                    if len(vuln_regs) == 3:
                        siz_reg = vuln_regs[0]
                    else:
                        siz_reg = None
                else:
                    fmt_reg = vuln_regs[-1]
                    if len(vuln_regs) == 2:
                        siz_reg = vuln_regs[0]
                    else:
                        siz_reg = None

                # 判断是否有size参数
                if siz_reg != None:
                    FELogger.info("从%s回溯字符串长度%s" % (num_to_hexstr(xref_addr_t), siz_reg))
                    siz_tracer = FEArgsTracer(xref_addr_t, siz_reg, max_node=256)
                    siz_source_addr = siz_tracer.run()
                    print('siz_source_addr: ', siz_source_addr)
                    # 判断是否找到size的地址
                    if siz_source_addr == []:
                        FELogger.info("未找到size地址%s" % num_to_hexstr(xref_addr_t))
                        check_fmt_reg(xref_addr_t, fmt_reg, args_rule, parse=True)
                    else:
                        for siz_addr_t in siz_source_addr:
                            # 判断size是否为立即数
                            if idc.get_operand_type(siz_addr_t, 1) != ida_ua.o_imm:
                                check_fmt_reg(xref_addr_t, fmt_reg, args_rule, siz_addr_t, parse=True)
                            else:
                                num = idc.print_operand(siz_addr_t, 1)
                                data = AnalysisChooseData(vuln=0, name=func_name_t, ea=xref_addr_t, addr1=siz_addr_t, str1='', other1=num)
                                items.append(data)
                else:
                    check_fmt_reg(xref_addr_t, fmt_reg, args_rule, parse=True)
    return items

def scanf_func_analysis(func_name, xref_list):
    """
    scanf系列函数漏洞分析
    """

    func_name_t = func_name
    xref_list_t = xref_list

    items = printf_func_analysis(func_name_t, xref_list_t)
    return items

def str_func_analysis(func_name, xref_list):
    """
    str操作类函数漏洞分析
    """

    def check_src_reg(xref_addr_t, src_reg, siz_addr_t=0):
        vuln_flag = 0
        addr1 = 0
        str1 = ''

        if siz_addr_t == 0:
            str_siz_addr = ''
        else:
            str_siz_addr = num_to_hexstr(siz_addr_t)

        FELogger.info("从%s回溯来源地址%s" % (num_to_hexstr(xref_addr_t), src_reg))
        src_tracer = FEArgsTracer(xref_addr_t, src_reg)
        src_source_addr = src_tracer.run()
        print('src_source_addr: ', src_source_addr)
        # 判断是否找到字符串来源地址
        if src_source_addr == []:
            FELogger.info("未找到目标地址%s" % num_to_hexstr(xref_addr_t))
            vuln_flag = 1
        else:
            for src_addr in src_source_addr:
                addr1 = src_addr
                src_str = FEStrMgr.get_mem_string(src_addr)
                # 判断是否找到字符串
                if src_str == []:
                    FELogger.info('来源字符串未找到%s' % num_to_hexstr(xref_addr_t))
                    vuln_flag = 1
                else:
                    # 判断来源地址是否为内存
                    str1 = src_str[0]
                    if idc.get_operand_type(src_addr, 1) != ida_ua.o_mem:
                        vuln_flag = 1
                    else:
                        vuln_flag = 0

        data = AnalysisChooseData(vuln=vuln_flag, name=func_name_t, ea=xref_addr_t, addr1=addr1, str1=str1, other1=str_siz_addr)
        items.append(data)

    func_name_t = func_name
    xref_list_t = xref_list
    items = []
    vuln_rule = SINK_FUNC[func_name_t]['vuln_rule']
    vuln_regs = vuln_rule[0]['vuln_regs']
    src_reg = vuln_regs[0]
    siz_reg = None
    if len(vuln_regs) == 2:
        siz_reg = vuln_regs[1]

    FELogger.info('检测%s漏洞' % vuln_rule[0]['vuln_type'])
    for xref_addr_t in xref_list_t:
        # 判断是否有size参数
        if siz_reg != None:
            FELogger.info("从%s回溯字符串长度%s" % (num_to_hexstr(xref_addr_t), siz_reg))
            siz_tracer = FEArgsTracer(xref_addr_t, siz_reg, max_node=256)
            siz_source_addr = siz_tracer.run()
            print('siz_source_addr: ', siz_source_addr)
            # 判断是否找到size的地址
            if siz_source_addr == []:
                FELogger.info("未找到size地址%s" % num_to_hexstr(xref_addr_t))
                data = AnalysisChooseData(vuln=1, name=func_name_t, ea=xref_addr_t)
                items.append(data)
            else:
                for siz_addr_t in siz_source_addr:
                    # 判断size是否为立即数
                    if idc.get_operand_type(siz_addr_t, 1) != ida_ua.o_imm:
                        check_src_reg(xref_addr_t, src_reg, siz_addr_t)
                    else:
                        num = idc.print_operand(siz_addr_t, 1)
                        data = AnalysisChooseData(vuln=0, name=func_name_t, ea=xref_addr_t, addr1=siz_addr_t, str1='', other1=num)
                        items.append(data)
        else:
            check_src_reg(xref_addr_t, src_reg)
    return items

def mem_func_analysis(func_name, xref_list):
    """
    mem系列函数漏洞分析
    """

    func_name_t = func_name
    xref_list_t = xref_list

    items = str_func_analysis(func_name_t, xref_list_t)
    return items

def system_func_analysis(func_name, xref_list):
    """
    system系列函数漏洞分析    
    """

    vuln_flag = 0
    addr1 = 0
    str1 = ''

    func_name_t = func_name
    xref_list_t = xref_list
    items = []
    vuln_rule = SINK_FUNC[func_name_t]['vuln_rule']
    vuln_reg = vuln_rule[0]['vuln_regs'][0]

    FELogger.info('检测%s漏洞' % vuln_rule[0]['vuln_type'])
    for xref_addr_t in xref_list_t:
        FELogger.info("从%s回溯来源地址%s" % (num_to_hexstr(xref_addr_t), vuln_reg))
        tracer = FEArgsTracer(xref_addr_t, vuln_reg)
        source_addr = tracer.run()
        print('source_addr: ', source_addr)
        # 判断是否找到目标地址
        if source_addr == []:
            FELogger.info("目标地址未找到%s" % num_to_hexstr(xref_addr_t))
            vuln_flag = 1
        else:
            for cmd_addr in source_addr:
                addr1 = cmd_addr
                # 判断字符串是否来自内存
                if idc.get_operand_type(cmd_addr, 1) == ida_ua.o_mem:
                    cmd_str = FEStrMgr.get_mem_string(cmd_addr)
                    # 判断是否找到字符串
                    if cmd_str == []:
                        FELogger.info("硬编码命令未找到%s" % num_to_hexstr(xref_addr_t))
                        vuln_flag = 1
                    else:
                        vuln_flag = 0
                        str1 = cmd_str[0]
                else:
                    FELogger.info("命令来自外部%s" % num_to_hexstr(xref_addr_t))
                    vuln_flag = 1

        data = AnalysisChooseData(vuln=vuln_flag, name=func_name_t, ea=xref_addr_t, addr1=addr1, str1=str1)
        items.append(data)
    return items


class FEStaticForm(ida_kernwin.Form):
    """
    静态分析窗口
    """

    sink_func_xref_dict = {}
    vuln_func_fast_dict = {}    # 缓存，避免重复分析
    vuln_func_dict = {}
    tmp_func_dict = {}

    def __init__(self):
        ida_kernwin.Form.__init__(self, """STARTITEM 0
Firmeye Static Analyzer
危险函数地址:
<##查看:{btn_get_sink_func_addr}>
对指定函数调用地址下断点:
<##添加断点:{btn_add_tmp_func_bpt}><##删除断点:{btn_del_tmp_func_bpt}><##仅添加函数:{btn_add_tmp_func_info}>
危险函数调用地址（全部）:
<##查看:{btn_get_all_sink_func_xref}><##添加断点:{btn_add_all_xref_bpt}><##删除断点:{btn_del_all_xref_bpt}>
危险函数调用地址（指定）:
<##查看:{btn_get_one_sink_func_xref}><##添加断点:{btn_add_one_xref_bpt}><##删除断点:{btn_del_one_xref_bpt}>
危险函数漏洞分析（全部）:
<##查看:{btn_get_all_vuln_func}><##添加断点:{btn_add_all_vuln_bpt}><##删除断点:{btn_del_all_vuln_bpt}>
危险函数漏洞分析（指定）:
<##查看:{btn_get_one_vuln_func}><##添加断点:{btn_add_one_vuln_bpt}><##删除断点:{btn_del_one_vuln_bpt}>
给所有断点的下一条指令下断点:
<##添加断点:{btn_add_next_inst_bpt}><##添加并删除当前断点:{btn_add_next_and_del_inst_bpt}>
导出/导入离线断点:
<##导出:{btn_export_all_bpt_addr}><##导入:{btn_import_all_bpt_addr}>
""", {
    'btn_get_sink_func_addr': ida_kernwin.Form.ButtonInput(self.btn_get_sink_func_addr),

    'btn_get_all_sink_func_xref': ida_kernwin.Form.ButtonInput(self.btn_get_all_sink_func_xref),
    'btn_get_one_sink_func_xref': ida_kernwin.Form.ButtonInput(self.btn_get_one_sink_func_xref),
    'btn_get_all_vuln_func': ida_kernwin.Form.ButtonInput(self.btn_get_all_vuln_func),
    'btn_get_one_vuln_func': ida_kernwin.Form.ButtonInput(self.btn_get_one_vuln_func),

    'btn_add_all_xref_bpt': ida_kernwin.Form.ButtonInput(self.btn_add_all_xref_bpt),
    'btn_del_all_xref_bpt': ida_kernwin.Form.ButtonInput(self.btn_del_all_xref_bpt),
    'btn_add_one_xref_bpt': ida_kernwin.Form.ButtonInput(self.btn_add_one_xref_bpt),
    'btn_del_one_xref_bpt': ida_kernwin.Form.ButtonInput(self.btn_del_one_xref_bpt),
    'btn_add_all_vuln_bpt': ida_kernwin.Form.ButtonInput(self.btn_add_all_vuln_bpt),
    'btn_del_all_vuln_bpt': ida_kernwin.Form.ButtonInput(self.btn_del_all_vuln_bpt),
    'btn_add_one_vuln_bpt': ida_kernwin.Form.ButtonInput(self.btn_add_one_vuln_bpt),
    'btn_del_one_vuln_bpt': ida_kernwin.Form.ButtonInput(self.btn_del_one_vuln_bpt),
    'btn_add_tmp_func_bpt': ida_kernwin.Form.ButtonInput(self.btn_add_tmp_func_bpt),
    'btn_del_tmp_func_bpt': ida_kernwin.Form.ButtonInput(self.btn_del_tmp_func_bpt),
    'btn_add_tmp_func_info': ida_kernwin.Form.ButtonInput(self.btn_add_tmp_func_info),
    'btn_add_next_inst_bpt': ida_kernwin.Form.ButtonInput(self.btn_add_next_inst_bpt),
    'btn_add_next_and_del_inst_bpt': ida_kernwin.Form.ButtonInput(self.btn_add_next_and_del_inst_bpt),
    'btn_export_all_bpt_addr': ida_kernwin.Form.ButtonInput(self.btn_export_all_bpt_addr),
    'btn_import_all_bpt_addr': ida_kernwin.Form.ButtonInput(self.btn_import_all_bpt_addr),
})

    def add_or_del_all_xref_bpt(self, is_add):
        if is_add == True:
            action = idc.add_bpt
            act_info = '添加'
        else:
            action = idc.del_bpt
            act_info = '删除'

        if self.sink_func_xref_dict == {}:
            mgr_t = FESinkFuncMgr()
            for func_name, xref_list in mgr_t.gen_sink_func_xref():
                tmp_list = []
                for xref_addr_t in xref_list:
                    tmp_list.append(xref_addr_t)
                    action(xref_addr_t)
                self.sink_func_xref_dict[func_name] = tmp_list
        else:
            for xref_addr_t in reduce(lambda x, y: x+y, self.sink_func_xref_dict.values()):
                action(xref_addr_t)
        FELogger.info('已%s断点：危险函数调用地址（全部）' % act_info)

    def btn_add_all_xref_bpt(self, code=0):
        """添加断点 所有危险函数调用地址"""
        self.add_or_del_all_xref_bpt(is_add=True)

    def btn_del_all_xref_bpt(self, code=0):
        """删除断点 所有危险函数调用地址"""
        self.add_or_del_all_xref_bpt(is_add=False)

    def add_or_del_one_xref_bpt(self, is_add):
        if is_add == True:
            action = idc.add_bpt
            act_info = '添加'
        else:
            action = idc.del_bpt
            act_info = '删除'

        tgt_t = ida_kernwin.ask_str('', 0, '请输入危险函数名')
        if tgt_t in SINK_FUNC:
            if not tgt_t in self.sink_func_xref_dict:
                mgr_t = FESinkFuncMgr()
                xref_list = mgr_t.get_one_func_xref(tgt_t)

                if not xref_list:
                    FELogger.warn("未找到函数%s" % tgt_t)
                    return

                tmp_list = []
                for xref_addr in xref_list:
                    tmp_list.append(xref_addr)
                    action(xref_addr)
                self.sink_func_xref_dict[tgt_t] = tmp_list
            else:
                for xref_addr_t in self.sink_func_xref_dict[tgt_t]:
                    action(xref_addr_t)
            FELogger.info("已%s断点：危险函数调用地址（%s）" % (act_info, tgt_t))
        else:
            FELogger.warn("未支持函数")

    def btn_add_one_xref_bpt(self, code=0):
        """添加断点 某个危险函数调用地址"""
        self.add_or_del_one_xref_bpt(is_add=True)

    def btn_del_one_xref_bpt(self, code=0):
        """删除断点 某个危险函数调用地址"""
        self.add_or_del_one_xref_bpt(is_add=False)

    def btn_add_all_vuln_bpt(self, code=0):
        """添加断点 所有危险函数漏洞地址"""
        self.add_fast_dict_from_all_vuln_func()

        for xref_addr_t in reduce(lambda x, y: x + y, self.vuln_func_fast_dict.values()):
            ida_dbg.add_bpt(xref_addr_t, 0, idc.BPT_DEFAULT)

        FELogger.info('已添加断点：危险函数漏洞分析（全部）')

    def btn_del_all_vuln_bpt(self, code=0):
        """删除断点 所有危险函数漏洞地址"""
        for xref_addr_t in reduce(lambda x, y: x + y, self.vuln_func_fast_dict.values()):
            ida_dbg.del_bpt(xref_addr_t)

        FELogger.info('已删除断点：危险函数漏洞分析（全部）')

    def btn_add_one_vuln_bpt(self, code=0):
        """添加断点 某个危险函数漏洞地址"""
        tgt_t = ida_kernwin.ask_str('', 0, '请输入危险函数名')
        if tgt_t in SINK_FUNC:
            if not tgt_t in self.vuln_func_fast_dict:
                mgr_t = FESinkFuncMgr()
                xref_list = mgr_t.get_one_func_xref(tgt_t)
                tag = SINK_FUNC[tgt_t]['tag']

                if not xref_list:
                    FELogger.warn("未找到函数%s" % tgt_t)
                    return

                if tag == FUNC_TAG['PRINTF']:
                    items = printf_func_analysis(tgt_t, xref_list)
                    self.add_fast_dict_from_items(items)
                elif tag == FUNC_TAG['STRING']:
                    items = str_func_analysis(tgt_t, xref_list)
                    self.add_fast_dict_from_items(items)
                elif tag == FUNC_TAG['SCANF']:
                    items = scanf_func_analysis(tgt_t, xref_list)
                    self.add_fast_dict_from_items(items)
                elif tag == FUNC_TAG['SYSTEM']:
                    items = system_func_analysis(tgt_t, xref_list)
                    self.add_fast_dict_from_items(items)
                elif tag == FUNC_TAG['MEMORY']:
                    items = mem_func_analysis(tgt_t, xref_list)
                    self.add_fast_dict_from_items(items)
                else:
                    FELogger.info("未支持函数%s" % tgt_t)

            if tgt_t in self.vuln_func_fast_dict:
                for xref_addr_t in self.vuln_func_fast_dict[tgt_t]:
                    ida_dbg.add_bpt(xref_addr_t, 0, idc.BPT_DEFAULT)

            FELogger.info('已添加断点：危险函数漏洞分析（%s）' % tgt_t)
        else:
            FELogger.warn("未支持函数")

    def btn_del_one_vuln_bpt(self, code=0):
        """删除断点 某个危险函数漏洞地址"""
        tgt_t = ida_kernwin.ask_str('', 0, '请输入危险函数名')
        if tgt_t in SINK_FUNC:
            if tgt_t in self.vuln_func_fast_dict:
                for xref_addr_t in self.vuln_func_fast_dict[tgt_t]:
                    ida_dbg.del_bpt(xref_addr_t)
            FELogger.info("已删除断点：危险函数漏洞分析（%s）" % tgt_t)
        else:
            FELogger.warn("未支持函数")

    def add_tmp_func(self, info_only=False):
        """
        添加临时sink函数
        info_only: 在添加函数信息的同时是否添加断点
        """

        input_str = ida_kernwin.ask_text(0, '', "请输入任意函数名/函数地址，及各参数类型（none, int, str），可输入多行\n例如：\nstrcmp str str")
        try:
            rules = [x.strip() for x in input_str.strip().split('\n')]
            for rule in rules:
                tgt_t = rule.split(' ')[0].strip()
                args_rule = [x.strip() for x in rule.split(' ')[1:]]

                if not tgt_t in self.tmp_func_dict:
                    if tgt_t.startswith('0x'):
                        addr_t = int(tgt_t, 16)
                        addr_hexstr = num_to_hexstr(addr_t)
                        CUSTOM_FUNC[addr_hexstr] = {'args_rule': args_rule}
                        self.tmp_func_dict[addr_hexstr] = [addr_t]
                        if info_only == False:
                            ida_dbg.add_bpt(addr_t, 0, idc.BPT_DEFAULT)
                    else:
                        for func_addr_t in idautils.Functions():
                            func_name_t = ida_funcs.get_func_name(func_addr_t)
                            if func_name_t == tgt_t:
                                CUSTOM_FUNC[func_name_t] = {'args_rule': args_rule}
                                self.tmp_func_dict[func_name_t] = []
                                for xref_addr_t in idautils.CodeRefsTo(func_addr_t, 0):
                                    self.tmp_func_dict[func_name_t].append(xref_addr_t)
                                    if info_only == False:
                                        ida_dbg.add_bpt(xref_addr_t, 0, idc.BPT_DEFAULT)
                                    else:
                                        continue
                                break
                            else:
                                continue
                else:
                    CUSTOM_FUNC[tgt_t] = {'args_rule': args_rule}
                    for xref_addr_t in self.tmp_func_dict[tgt_t]:
                        if info_only == False:
                            ida_dbg.add_bpt(xref_addr_t, 0, idc.BPT_DEFAULT)
                        else:
                            continue
                FELogger.info("已添加断点：%s" % rule)
        except Exception as e:
            FELogger.info("输入信息有误：%s" % e)

    def btn_add_tmp_func_bpt(self, code=0):
        """添加临时函数并下断点"""
        self.add_tmp_func(info_only=False)

    def btn_del_tmp_func_bpt(self, code=0):
        """删除临时函数断点"""
        tgt_t = ida_kernwin.ask_str('', 0, '请输入任意函数名')
        try:
            if tgt_t in self.tmp_func_dict:
                for xref_addr_t in self.tmp_func_dict[tgt_t]:
                    ida_dbg.del_bpt(xref_addr_t)
                CUSTOM_FUNC.pop(tgt_t)
            FELogger.info("已删除断点：指定函数调用地址 %s" % tgt_t)
        except Exception:
            FELogger.warn("请输入函数名")

    def btn_add_tmp_func_info(self, code=0):
        """添加临时函数"""
        self.add_tmp_func(info_only=True)

    def get_all_bpt_list(self):
        """
        获取所有断点的地址列表
        """
        bpt_list = []
        bpt_num = ida_dbg.get_bpt_qty()
        bpt_t = ida_dbg.bpt_t()
        for i in range(bpt_num):
            if ida_dbg.getn_bpt(i, bpt_t) == True:
                bpt_list.append(bpt_t.ea)
            else:
                FELogger.info("获取断点失败 %d" % i)
        return bpt_list

    def btn_add_next_inst_bpt(self, code=0):
        """
        给所有断点的下一条指令下断点
        """
        bpt_list = self.get_all_bpt_list()
        for bpt in bpt_list:
            ida_dbg.add_bpt(ida_bytes.next_head(bpt, ida_idaapi.BADADDR), 0, idc.BPT_DEFAULT)

    def btn_add_next_and_del_inst_bpt(self, code=0):
        """
        给所有断点的下一条指令下断点并删除当前断点
        """
        bpt_list = self.get_all_bpt_list()
        for bpt in bpt_list:
            ida_dbg.add_bpt(ida_bytes.next_head(bpt, ida_idaapi.BADADDR), 0, idc.BPT_DEFAULT)
            ida_dbg.del_bpt(bpt)

    def btn_export_all_bpt_addr(self, code=0):
        """
        导出离线断点
        """
        cur_workpath_t = os.getcwd()
        csv_filepath_t = os.path.join(cur_workpath_t, '%s_bpt.csv' % ida_nalt.get_root_filename())

        bpt_list = self.get_all_bpt_list()
        bpt_list = [[format(bpt, '#010x')[2:]] for bpt in bpt_list]

        header = ['breakpoints']
        with open(csv_filepath_t, 'w', newline='') as f:
            ff = csv.writer(f)
            ff.writerow(header)
            ff.writerows(bpt_list)

        FELogger.info("导出断点完成：%s" % csv_filepath_t)

    def btn_import_all_bpt_addr(self, code=0):
        """
        导入离线断点
        """
        cur_workpath_t = os.getcwd()
        csv_filepath_t = os.path.join(cur_workpath_t, '%s_bpt.csv' % ida_nalt.get_root_filename())

        if os.path.exists(csv_filepath_t):
            with open(csv_filepath_t, 'r') as f:
                next(f)
                reader = csv.reader(f)
                for row in reader:
                    ida_dbg.add_bpt(int(row[0], 16), 0, idc.BPT_DEFAULT)
            FELogger.info("导入断点完成：%s" % csv_filepath_t)
        else:
            FELogger.warn("文件不存在：%s" % csv_filepath_t)

    def btn_get_sink_func_addr(self, code=0):
        """
        查看危险函数地址列表
        """
        cols = [['', 0 | ida_kernwin.Choose.CHCOL_DEC],
                ['函数名', 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                ['函数地址', 10 | ida_kernwin.Choose.CHCOL_HEX]]
        items = []

        mgr_t = FESinkFuncMgr()
        for func_name, func_addr in mgr_t.gen_sink_func_addr():
            data = AnalysisChooseData(vuln=0, name=func_name, ea=func_addr)
            items.append(data)

        chooser = AnalysisChooser(title='危险函数地址', cols=cols, item=items)
        chooser.Show()

    def btn_get_all_sink_func_xref(self, code=0):
        """
        查看所有危险函数调用地址
        """

        cols = [['', 0 | ida_kernwin.Choose.CHCOL_DEC],
                ['函数名', 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                ['函数地址', 10 | ida_kernwin.Choose.CHCOL_HEX]]
        items = []

        mgr_t = FESinkFuncMgr()
        for func_name, xref_list in mgr_t.gen_sink_func_xref():
            tmp_list = []
            for xref_addr in xref_list:
                data = AnalysisChooseData(vuln=0, name=func_name, ea=xref_addr)
                items.append(data)
                tmp_list.append(xref_addr)
            self.sink_func_xref_dict[func_name] = tmp_list

        chooser = AnalysisChooser(title='危险函数调用地址', cols=cols, item=items)
        chooser.Show()

    def btn_get_one_sink_func_xref(self, code=0):
        """
        查看某个危险函数调用地址
        """

        tgt_t = ida_kernwin.ask_str('', 0, '请输入要查看的危险函数名')
        if tgt_t in SINK_FUNC:
            cols = [['', 0 | ida_kernwin.Choose.CHCOL_DEC],
                ['函数名', 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                ['函数地址', 10 | ida_kernwin.Choose.CHCOL_HEX]]
            items = []

            mgr_t = FESinkFuncMgr()
            xref_list = mgr_t.get_one_func_xref(tgt_t)

            if not xref_list:
                FELogger.warn("未找到函数%s" % tgt_t)
                return

            tmp_list = []
            for xref_addr in xref_list:
                data = AnalysisChooseData(vuln=0, name=tgt_t, ea=xref_addr)
                items.append(data)
                tmp_list.append(xref_addr)
            self.sink_func_xref_dict[tgt_t] = tmp_list

            chooser = AnalysisChooser(title='危险函数调用地址', cols=cols, item=items)
            chooser.Show()
        else:
            FELogger.warn("未支持函数")

    def get_vuln_addr_from_items(self, items):
        vuln_list = set()
        for item in items:
            if item.vuln == 1:
                vuln_list.add(item.ea)
            else:
                continue
        return list(vuln_list)

    def add_fast_dict_from_items(self, items):
        if items != []:
            func_name = items[0].name
            vuln_list = self.get_vuln_addr_from_items(items)
            self.vuln_func_fast_dict[func_name] = vuln_list

    def add_fast_dict_from_all_vuln_func(self):
        mgr_t = FESinkFuncMgr()
        for func_name, xref_list in mgr_t.gen_sink_func_xref():
            if not func_name in self.vuln_func_fast_dict:
                tag = SINK_FUNC[func_name]['tag']
                print('func_name: ', func_name)
                print('xref_list: ', len(xref_list))
                if tag == FUNC_TAG['PRINTF']:
                    items = printf_func_analysis(func_name, xref_list)
                    self.add_fast_dict_from_items(items)
                elif tag == FUNC_TAG['STRING']:
                    items = str_func_analysis(func_name, xref_list)
                    self.add_fast_dict_from_items(items)
                elif tag == FUNC_TAG['SCANF']:
                    items = scanf_func_analysis(func_name, xref_list)
                    self.add_fast_dict_from_items(items)
                elif tag == FUNC_TAG['SYSTEM']:
                    items = system_func_analysis(func_name, xref_list)
                    self.add_fast_dict_from_items(items)
                elif tag == FUNC_TAG['MEMORY']:
                    items = mem_func_analysis(func_name, xref_list)
                    self.add_fast_dict_from_items(items)
                else:
                    FELogger.info("未支持函数%s" % func_name)
            else:
                continue

    def btn_get_all_vuln_func(self, code=0):
        """查看所有危险函数漏洞地址"""
        self.add_fast_dict_from_all_vuln_func()

    def btn_get_one_vuln_func(self, code=0):
        """查看某个危险函数漏洞地址"""
        tgt_t = ida_kernwin.ask_str('', 0, '请输入要查看的危险函数名')
        if tgt_t in SINK_FUNC:
            mgr_t = FESinkFuncMgr()
            xref_list = mgr_t.get_one_func_xref(tgt_t)
            tag = SINK_FUNC[tgt_t]['tag']

            if not xref_list:
                FELogger.warn("未找到函数%s" % tgt_t)
                return

            # printf系列函数
            if tag == FUNC_TAG['PRINTF']:
                items = printf_func_analysis(tgt_t, xref_list)
                self.add_fast_dict_from_items(items)
                cols = [['可疑', 3 | ida_kernwin.Choose.CHCOL_DEC],
                        ['函数名', 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['函数地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['格式字符串地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['格式字符串', 15 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['长度', 10 | ida_kernwin.Choose.CHCOL_HEX]]
                chooser = AnalysisChooser(title='危险函数漏洞分析', cols=cols, item=items)
                chooser.Show()

            # str系列函数
            elif tag == FUNC_TAG['STRING']:
                items = str_func_analysis(tgt_t, xref_list)
                self.add_fast_dict_from_items(items)
                cols = [['可疑', 3 | ida_kernwin.Choose.CHCOL_DEC],
                        ['函数名', 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['函数地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['来源地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['字符串', 15 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['字符串长度', 10 | ida_kernwin.Choose.CHCOL_HEX]]
                chooser = AnalysisChooser(title='危险函数漏洞分析', cols=cols, item=items)
                chooser.Show()

            # scanf系列函数
            elif tag == FUNC_TAG['SCANF']:
                items = scanf_func_analysis(tgt_t, xref_list)
                self.add_fast_dict_from_items(items)
                cols = [['可疑', 3 | ida_kernwin.Choose.CHCOL_DEC],
                        ['函数名', 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['函数地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['格式字符串地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['格式字符串', 15 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['长度', 10 | ida_kernwin.Choose.CHCOL_HEX]]
                chooser = AnalysisChooser(title='危险函数漏洞分析', cols=cols, item=items)
                chooser.Show()

            # system函数
            elif tag == FUNC_TAG['SYSTEM']:
                items = system_func_analysis(tgt_t, xref_list)
                self.add_fast_dict_from_items(items)
                cols = [['可疑', 3 | ida_kernwin.Choose.CHCOL_DEC],
                        ['函数名', 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['函数地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['来源地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['命令语句', 15 | ida_kernwin.Choose.CHCOL_PLAIN]]
                chooser = AnalysisChooser(title='危险函数漏洞分析', cols=cols, item=items)
                chooser.Show()

            # mem系列函数
            elif tag == FUNC_TAG['MEMORY']:
                items = mem_func_analysis(tgt_t, xref_list)
                self.add_fast_dict_from_items(items)
                cols = [['可疑', 3 | ida_kernwin.Choose.CHCOL_DEC],
                        ['函数名', 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['函数地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['来源地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ['', 0 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['字符串长度', 10 | ida_kernwin.Choose.CHCOL_HEX]]
                chooser = AnalysisChooser(title='危险函数漏洞分析', cols=cols, item=items)
                chooser.Show()
            else:
                FELogger.info("未支持函数%s" % tgt_t)
        else:
            FELogger.warn("未支持函数")


class FEStaticAnalyzer(ida_kernwin.action_handler_t):
    """
    静态分析器
    """

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def show_menu(self):
        main = FEStaticForm()
        main.Compile()
        main.Execute()

    @FELogger.reload
    def activate(self, ctx):
        self.show_menu()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
