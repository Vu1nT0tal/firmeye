# -*- coding: utf-8 -*-

import ida_idaapi
import ida_kernwin

from firmeye.utility import FirmEyeStrMgr
from firmeye.constants import *
from firmeye.logger import FirmEyeLogger
from firmeye.analysis.static import FirmEyeStaticAnalyzer
from firmeye.analysis.dynamic import FirmEyeDynamicAnalyzer
from firmeye.re_assistant import FirmEyeReAssist
from firmeye.test import FirmEyeFuncTest

MENU_PATH = "Edit/Plugins/"


class Firmeye(ida_idaapi.plugin_t):
    help = PLUGIN_HELP
    flags = ida_idaapi.PLUGIN_KEEP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    comment = PLUGIN_COMMENT

    def __init__(self):
        ida_idaapi.plugin_t.__init__(self)
        FirmEyeStrMgr(minl=1)

    act_static = 'firmeye:static_main'
    act_dbg_hook = 'firmeye:dynamic_change_debug_hook_mode'
    act_assist = 'firmeye:reverse_assistant'
    act_test = 'firmeye:functional_test'

    def _init_actions(self):
        action_t = ida_kernwin.action_desc_t(
            self.act_static,
            'static analyzer: main menu',
            FirmEyeStaticAnalyzer(),
            'Ctrl+Shift+s',
            '静态分析器主菜单', 0)
        ida_kernwin.register_action(action_t)
        ida_kernwin.attach_action_to_menu(MENU_PATH, self.act_static, ida_kernwin.SETMENU_APP)

        action_t = ida_kernwin.action_desc_t(
            self.act_dbg_hook,
            'dynamic analyzer: enable/disable debug hook',
            FirmEyeDynamicAnalyzer(),
            'Ctrl+Shift+d',
            '启用/解除DEBUG Hook', 0)
        ida_kernwin.register_action(action_t)
        ida_kernwin.attach_action_to_menu(MENU_PATH, self.act_dbg_hook, ida_kernwin.SETMENU_APP)

        action_t = ida_kernwin.action_desc_t(
            self.act_test,
            'reverse assist tools',
            FirmEyeReAssist(),
            'Ctrl+Shift+x',
            '逆向辅助工具', 0)
        ida_kernwin.register_action(action_t)
        ida_kernwin.attach_action_to_menu(MENU_PATH, self.act_assist, ida_kernwin.SETMENU_APP)

        action_t = ida_kernwin.action_desc_t(
            self.act_test,
            'functional test',
            FirmEyeFuncTest(),
            'Ctrl+Shift+q',
            '功能性测试', 0)
        ida_kernwin.register_action(action_t)
        ida_kernwin.attach_action_to_menu(MENU_PATH, self.act_test, ida_kernwin.SETMENU_APP)

    def _detach_menu_action(self):
        ida_kernwin.detach_action_from_menu(MENU_PATH, self.act_static)
        ida_kernwin.detach_action_from_menu(MENU_PATH, self.act_dbg_hook)
        ida_kernwin.detach_action_from_menu(MENU_PATH, self.act_assist)
        ida_kernwin.detach_action_from_menu(MENU_PATH, self.act_test)

    def _install_plugins(self):
        self._init_actions()

    def init(self):
        try:
            self._install_plugins()
        except Exception as e:
            FirmEyeLogger.erro(e.__str__())
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        self._detach_menu_action()

    def banner(self):
        FirmEyeLogger.console(PLUGIN_HELP)
        FirmEyeLogger.console(BANNER_MSG)

    def run(self,arg):
        self.banner()

def PLUGIN_ENTRY():
    try:
        return Firmeye()
    except Exception as e:
        FirmEyeLogger.erro(e.__str__())
