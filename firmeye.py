# -*- coding: utf-8 -*-

import idaapi

from firmeye.utility import *
from firmeye.constants import *
#from firmeye.logger import *
from firmeye.analysis.static import FirmEyeStaticAnalyzer
from firmeye.analysis.dynamic import FirmEyeDynamicAnalyzer
from firmeye.test import FirmEyeFuncTest

MENU_PATH = "Edit/Plugins/"


class Firmeye(idaapi.plugin_t):
    help = PLUGIN_HELP
    flags = idaapi.PLUGIN_KEEP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    comment = PLUGIN_COMMENT

    def __init__(self):
        super(Firmeye, self).__init__()
        FirmEyeStrMgr(minl=1)

    act_static = 'firmeye:static_main'
    act_dbg_hook = 'firmeye:dynamic_change_debug_hook_mode'
    act_assist = 'firmeye:reverse_assistant'
    act_test = 'firmeye:functional_test'

    def _init_actions(self):
        action_t = idaapi.action_desc_t(
            self.act_static,
            'static analyzer: main menu',
            FirmEyeStaticAnalyzer(),
            'Ctrl+Shift+s',
            '静态分析器主菜单', 0)
        idaapi.register_action(action_t)
        idaapi.attach_action_to_menu(MENU_PATH, self.act_static, idaapi.SETMENU_APP)

        action_t = idaapi.action_desc_t(
            self.act_dbg_hook,
            'dynamic analyzer: enable/disable debug hook',
            FirmEyeDynamicAnalyzer(),
            'Ctrl+Shift+d',
            '启用/解除DEBUG Hook', 0)
        idaapi.register_action(action_t)
        idaapi.attach_action_to_menu(MENU_PATH, self.act_dbg_hook, idaapi.SETMENU_APP)

        action_t = idaapi.action_desc_t(
            self.act_test,
            'functional test',
            FirmEyeFuncTest(),
            'Ctrl+Shift+q',
            '功能性测试', 0)
        idaapi.register_action(action_t)
        idaapi.attach_action_to_menu(MENU_PATH, self.act_test, idaapi.SETMENU_APP)

    def _detach_menu_action(self):
        idaapi.detach_action_from_menu(MENU_PATH, self.act_static)
        idaapi.detach_action_from_menu(MENU_PATH, self.act_dbg_hook)
        idaapi.detach_action_from_menu(MENU_PATH, self.act_test)

    def _install_plugins(self):
        self._init_actions()

    def init(self):
        try:
            self._install_plugins()
        except Exception as e:
            FirmEyeLogger.erro(e.__str__())
        return idaapi.PLUGIN_KEEP

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
