# -*- coding: utf-8 -*-

import ida_funcs
import ida_kernwin
import idautils

from firmeye.utility import FEArgsTracer
from firmeye.helper import hexstr
from firmeye.logger import FELogger


class FEFuncTestForm(ida_kernwin.Form):

    def __init__(self):
        ida_kernwin.Form.__init__(self, """STARTITEM 0
Functional Test
DFS测试（从某地址回溯某寄存器）：
<##测试:{btn_dfs_test_1}>
DFS测试（从某函数所有调用地址回溯某寄存器）：
<##测试:{btn_dfs_test_2}>
""", {
    'btn_dfs_test_1': ida_kernwin.Form.ButtonInput(self.btn_dfs_test_1),
    'btn_dfs_test_2': ida_kernwin.Form.ButtonInput(self.btn_dfs_test_2)
})

    def btn_dfs_test_1(self, code=0):
        addr_t = ida_kernwin.ask_str('', 0, '请输入回溯起点地址')
        reg_t = ida_kernwin.ask_str('', 0, '请输入回溯寄存器')
        if (addr_t and addr_t != '') and (reg_t and reg_t != ''):
            try:
                addr_t = int(addr_t, 16)
            except Exception:
                FELogger.warn("无效地址")
                return

            FELogger.info("从地址%s回溯寄存器%s" % (hexstr(addr_t), reg_t))
            tracer = FEArgsTracer(addr_t, reg_t)
            source_addr = tracer.run()
            print('source_addr: ', source_addr)
        else:
            FELogger.warn("请输入起点地址和寄存器")

    def btn_dfs_test_2(self, code=0):
        tgt_t = ida_kernwin.ask_str('', 0, '请输入函数名')
        reg_t = ida_kernwin.ask_str('', 0, '请输入回溯寄存器')
        if (tgt_t and tgt_t != '') and (reg_t and reg_t != ''):
            for func_addr_t in idautils.Functions():
                func_name_t = ida_funcs.get_func_name(func_addr_t)
                if func_name_t == tgt_t:
                    for xref_addr_t in idautils.CodeRefsTo(func_addr_t, 0):
                        if ida_funcs.get_func(xref_addr_t):
                            FELogger.info("从地址%s回溯寄存器%s" % (hexstr(xref_addr_t), reg_t))
                            tracer = FEArgsTracer(xref_addr_t, reg_t, max_node=256)
                            source_addr = tracer.run()
                            print('source_addr: ', source_addr)
                    break
            else:
                FELogger.warn("请输入函数名和寄存器")


class FEFuncTest(ida_kernwin.action_handler_t):
    """功能测试器
    DFS寄存器回溯测试
    """

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def show_menu(self):
        main = FEFuncTestForm()
        main.Compile()
        main.Execute()

    @FELogger.reload
    def activate(self, ctx):
        self.show_menu()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
