# -*- coding: utf-8 -*-  

import idc
import idaapi
import idautils

from firmeye.utility import *
from firmeye.logger import FirmEyeLogger


class FirmEyeFuncTestForm(idaapi.Form):

    def __init__(self):
        super(FirmEyeFuncTestForm, self).__init__("""STARTITEM 0
Functional Test
DFS测试（从某地址回溯某寄存器）：
<##测试:{btn_dfs_test_1}>
DFS测试（从某函数所有调用地址回溯某寄存器）：
<##测试:{btn_dfs_test_2}>
""", {
    'btn_dfs_test_1': idaapi.Form.ButtonInput(self.btn_dfs_test_1),
    'btn_dfs_test_2': idaapi.Form.ButtonInput(self.btn_dfs_test_2)
})

    def btn_dfs_test_1(self, code=0):
        addr_t = idaapi.ask_str('', 0, '请输入回溯起点地址')
        reg_t = idaapi.ask_str('', 0, '请输入回溯寄存器')
        if (addr_t and addr_t != '') and (reg_t and reg_t != ''):
            try:
                addr_t = int(addr_t, 16)
            except Exception:
                FirmEyeLogger.warn("无效地址")
                return

            FirmEyeLogger.info("从地址%s回溯寄存器%s" % (num_to_hexstr(addr_t), reg_t))
            tracer = FirmEyeArgsTracer(addr_t, reg_t)
            source_addr = tracer.run()
            print 'source_addr: ', source_addr
        else:
            FirmEyeLogger.warn("请输入起点地址和寄存器")

    def btn_dfs_test_2(self, code=0):
        tgt_t = idaapi.ask_str('', 0, '请输入函数名')
        reg_t = idaapi.ask_str('', 0, '请输入回溯寄存器')
        if (tgt_t and tgt_t != '') and (reg_t and reg_t != ''):
            for func_addr_t in idautils.Functions():
                func_name_t = idaapi.get_func_name(func_addr_t)
                if func_name_t == tgt_t:
                    for xref_addr_t in idautils.CodeRefsTo(func_addr_t, 0):
                        if idaapi.get_func(xref_addr_t):
                            FirmEyeLogger.info("从地址%s回溯寄存器%s" % (num_to_hexstr(xref_addr_t), reg_t))
                            tracer = FirmEyeArgsTracer(xref_addr_t, reg_t, max_node=256)
                            source_addr = tracer.run()
                            print 'source_addr: ', source_addr
                    break
            else:
                FirmEyeLogger.warn("请输入函数名和寄存器")


class FirmEyeFuncTest(idaapi.action_handler_t):
    """功能测试器
    DFS寄存器回溯测试
    """

    def __init__(self):
        super(FirmEyeFuncTest, self).__init__()
    
    def show_menu(self):
        main = FirmEyeFuncTestForm()
        main.Compile()
        main.Execute()

    @FirmEyeLogger.reload
    def activate(self, ctx):
        self.show_menu()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
