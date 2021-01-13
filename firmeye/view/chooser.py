# -*- coding: utf-8 -*-

import ida_kernwin

from firmeye.view.custviewer import CustViewer
from firmeye.helper import num_to_hexstr


class AnalysisChooseData():
    """
    显示结果数据结构
    """
    def __init__(self, vuln, name, ea, addr1=None, addr2=None, str1=None, str2=None, other1=None):
        self.vuln = vuln
        self.name = name
        self.ea = ea
        self.addr1 = addr1
        self.addr2 = addr2
        self.str1 = str1
        self.str2 = str2
        self.other1 = other1


class AnalysisChooser(ida_kernwin.Choose):
    """
    分析结果窗口选择器
    """
    def __init__(self, title, cols, item):
        ida_kernwin.Choose.__init__(self,
            title=title, cols=cols, flags=(ida_kernwin.Choose.CH_QFLT | ida_kernwin.Choose.CH_NOIDB)
        )
        self.build_items(item)

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        d = self.items[n]
        data = [str(d.vuln), d.name, num_to_hexstr(d.ea)]

        for x in [d.vuln, d.addr2]:
            if x != None:
                data.append(num_to_hexstr(x))
            else:
                continue

        for x in [d.str1, d.str2, d.other1]:
            if x != None:
                data.append(x)
            else:
                continue

        return data

    def OnSelectLine(self, n):
        data = self.items[n]
        viewer = CustViewer(data.ea)
        viewer.jump_in_disassembly()
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def build_items(self, items):
        self.items = []
        for item in items:
            self.items.append(item)
