# -*- coding: utf-8 -*-

import os
import csv
from collections import OrderedDict

import idc
import ida_funcs
import ida_kernwin
import ida_auto
import ida_nalt
import idautils

from firmeye.helper import str_gbk_to_utf8, num_to_hexstr, str_utf8_to_gbk
from firmeye.logger import FirmEyeLogger
from firmeye.tools.idapyhelper import PyHelperChooser
from firmeye.view.chooser import AnalysisChooser, AnalysisChooseData
from firmeye.idaxml import XmlExporter, Cancelled


class FirmEyeReAssistForm(ida_kernwin.Form):

    def __init__(self):
        ida_kernwin.Form.__init__(self, """STARTITEM 0
Reverse Assistant
IDAPython帮助:
<##查看:{btn_idapy_helper}>
Ghidra函数列表
<##导入:{btn_imp_ghidra_funcs}>
函数调用次数统计
<##开始:{btn_func_xref_count}>
导出XML到Ghidra
<##导出:{btn_export_ida_to_xml}>
""", {
    'btn_idapy_helper': ida_kernwin.Form.ButtonInput(self.btn_idapy_helper),
    'btn_imp_ghidra_funcs': ida_kernwin.Form.ButtonInput(self.btn_imp_ghidra_funcs),
    'btn_func_xref_count': ida_kernwin.Form.ButtonInput(self.btn_func_xref_count),
    'btn_export_ida_to_xml': ida_kernwin.Form.ButtonInput(self.btn_export_ida_to_xml)
})

    def btn_idapy_helper(self, code=0):
        """
        IDAPython帮助
        """
        helper = PyHelperChooser("IDAPyHelper")
        helper.Show()

    def btn_imp_ghidra_funcs(self, code=0):
        """
        导入Ghidra函数列表
        """
        ghidra_filepath_t = os.path.join(os.getcwd(), 'ghidra_func_addrs.csv')
        ghidra_path_t = ida_kernwin.ask_str(str_gbk_to_utf8(ghidra_filepath_t), 0, '导入的Ghidra导出函数文件路径')

        func_addrs = list(idautils.Functions())
        make_func_addrs = []
        if ghidra_path_t and ghidra_path_t != '':
            if os.path.exists(str_utf8_to_gbk(ghidra_path_t)):
                with open(str_utf8_to_gbk(ghidra_path_t), 'rb') as f:
                    next(f)
                    reader = csv.reader(f)
                    for row in reader:
                        addr = int(row[0].strip('\"'), 16)
                        if ida_funcs.add_func(addr) == True:
                            make_func_addrs.append(addr)
                        else:
                            if addr not in func_addrs:
                                FirmEyeLogger.info("创建函数%s失败" % num_to_hexstr(addr))
                FirmEyeLogger.info("Ghidra导出函数文件：%s，已导入" % ghidra_path_t)
            else:
                FirmEyeLogger.erro("未找到Ghidra导出函数文件：%s" % ghidra_path_t)
        else:
            FirmEyeLogger.warn("请输入Ghidra导出函数文件路径")

        FirmEyeLogger.info("成功创建%d个新函数" % len(make_func_addrs))

    def btn_func_xref_count(self, code=0):
        """
        函数调用次数统计
        """
        xref_count_dict = OrderedDict()
        for func_addr_t in idautils.Functions():
            count = len(list(idautils.CodeRefsTo(func_addr_t, 0)))
            xref_count_dict[ida_funcs.get_func_name(func_addr_t)] = [func_addr_t, count]
        ordered_list = sorted(list(xref_count_dict.items()), key=lambda x: x[1][1], reverse=True)

        cols = [['', 0 | ida_kernwin.Choose.CHCOL_DEC],
                ['函数名', 15 | ida_kernwin.Choose.CHCOL_PLAIN],
                ['地址', 10 | ida_kernwin.Choose.CHCOL_HEX],
                ['次数', 10 | ida_kernwin.Choose.CHCOL_PLAIN]]
        items = []

        for x in ordered_list:
            data = AnalysisChooseData(vuln=0, name=x[0], ea=x[1][0], other1=str(x[1][1]))
            items.append(data)
        
        chooser = AnalysisChooser(title='函数调用次数统计', cols=cols, item=items)
        chooser.Show()
    
    def btn_export_ida_to_xml(self, code=0):
        """
        导出XML到Ghidra
        """
        def do_export():
            st = ida_auto.set_ida_state(idc.IDA_STATUS_WORK)
            xml = XmlExporter(1)

            try:
                try:
                    xml.export_xml()
                    FirmEyeLogger.info("已导出IDA数据到XML")
                except Cancelled:
                    ida_kernwin.hide_wait_box()
                    FirmEyeLogger.warn("已取消XML导出")
                except Exception:
                    ida_kernwin.hide_wait_box()
                    FirmEyeLogger.warn("导出XML失败")
            finally:
                xml.cleanup()
                ida_auto.set_ida_state(st)
        
        cur_workpath_t = os.getcwd()
        xml_filepath_t = os.path.join(cur_workpath_t, '%s.xml' % ida_nalt.get_input_file_path())
        bin_filepath_t = os.path.join(cur_workpath_t, '%s.bytes' % ida_nalt.get_input_file_path())

        if os.path.isfile(xml_filepath_t) and os.path.isfile(bin_filepath_t):
            if ida_kernwin.ask_yn(0, '导出文件已存在，是否覆盖？') == 1:
                do_export()
        else:
            do_export()


class FirmEyeReAssist(ida_kernwin.action_handler_t):
    """
    提供一些逆向辅助工具
    """

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def show_menu(self):
        main = FirmEyeReAssistForm()
        main.Compile()
        main.Execute()

    @FirmEyeLogger.reload
    def activate(self, ctx):
        self.show_menu()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
