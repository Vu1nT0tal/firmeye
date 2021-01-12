# -*- coding: utf-8 -*-

import re

import ida_bytes
import ida_kernwin

from firmeye.logger import FirmEyeLogger


class CustViewer(ida_kernwin.simplecustviewer_t):
    """
    分析结果窗口显示器
    """

    def __init__(self, ea):
        ida_kernwin.simplecustviewer_t.__init__(self)
        self.ea = ea

    def jump_in_disassembly(self):
        ea = self.ea
        if not ea or not ida_bytes.is_loaded(ea):
            FirmEyeLogger.warn("地址错误")
            return

        widget = self.find_disass_view()
        if not widget:
            FirmEyeLogger.warn("无法找到反汇编窗口")
            return

        self.jumpto_in_view(widget, ea)

    def jump_in_new_window(self):
        ea = self.ea
        if not ea or not ida_bytes.is_loaded(ea):
            FirmEyeLogger.warn("地址错误")
            return

        window_name = "D-0x%x" % ea
        widget = ida_kernwin.open_disasm_window(window_name)
        if widget:
            self.jumpto_in_view(widget, ea)
        else:
            FirmEyeLogger.warn("创建新窗口失败")

    def jump_in_hex(self):
        ea = self.ea
        if not ea or not ida_bytes.is_loaded(ea):
            FirmEyeLogger.warn("地址错误")
            return

        widget = self.find_hex_view()
        if not widget:
            FirmEyeLogger.warn("无法找到十六进制窗口")
            return

        self.jumpto_in_view(widget, ea)

    def find_disass_view(self):
        for c in map(chr, range(65, 75)):
            widget = ida_kernwin.find_widget('IDA View-%s' % c)
            if widget:
                return widget
            else:
                continue
        return None

    def find_hex_view(self):
        for i in range(1, 10):
            widget = ida_kernwin.find_widget('Hex View-%d' % i)
            if widget:
                return widget
            else:
                continue
        return None

    def jumpto_in_view(self, view, ea):
        ida_kernwin.activate_widget(view, True)
        return ida_kernwin.jumpto(ea)
