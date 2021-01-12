# -*- coding: utf-8 -*-

import os
import inspect

import ida_kernwin
import ida_diskio


class FileViewer(ida_kernwin.Form):
    """
    文件内容显示
    """

    def __init__(self, title, content):
        ida_kernwin.Form.__init__(self,
("BUTTON YES NONE\n"
"BUTTON NO NONE\n"
"BUTTON CANCEL NONE\n"
"%s\n\n"
"<##Docstring##:{cbEditable}>"
) % title,
{'cbEditable': ida_kernwin.Form.MultiLineTextControl(text=content,
    flags=ida_kernwin.textctrl_info_t.TXTF_READONLY |
    ida_kernwin.textctrl_info_t.TXTF_FIXEDFONT)})


class DocstringViewer(ida_kernwin.Form):
    """
    字符串显示
    """

    def __init__(self, title, docstr):
        ida_kernwin.Form.__init__(self,
("BUTTON YES NONE\n"
"BUTTON NO NONE\n"
"BUTTON CANCEL NONE\n"
"%s\n\n"
"<##Docstring##:{cbEditable}>"
) % title,
{'cbEditable': ida_kernwin.Form.MultiLineTextControl(text=docstr,
    flags=ida_kernwin.textctrl_info_t.TXTF_READONLY |
    ida_kernwin.textctrl_info_t.TXTF_FIXEDFONT)})


class ChooserData:
    """
    Chooser数据结构
    """

    icon_ids = {"str": 80, "int": 8, "class": 89, "function": 81, "method": 99}
    def __init__(self, mod_name, sym_name, file_name):
        self.mod_name = mod_name
        self.sym_name = sym_name
        self.file_name = file_name
        self.doc_str = ""
        self.sym_type = ""
        self.sym_value = ""
        self.line_no = ""

    def get_icon(self):
        return self.icon_ids[self.sym_type]


class PyHelperChooser(ida_kernwin.Choose):
    """
    Chooser
    """

    def __init__(self, title, nb=5):
        cols = [["模块", 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["符号", 20 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["文档", 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["类型", 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["取值", 10 | ida_kernwin.Choose.CHCOL_HEX],
                ["行号", 10 | ida_kernwin.Choose.CHCOL_DEC]]

        ida_kernwin.Choose.__init__(self,
            title=title, cols=cols, flags=ida_kernwin.Choose.CH_QFLT | ida_kernwin.Choose.CH_NOIDB
        )

        self.items = []
        self.icon = 0
        self.build_items()

    def build_items(self):
        pydir = ida_diskio.idadir("python3")
        for mod_name in os.listdir(pydir):
            if mod_name.endswith(".py"):
                mod_name, _ = os.path.splitext(mod_name)
                if mod_name in ["init", "idaapi"]:
                    continue
                else:
                    mod = __import__(mod_name)
                    file_name = mod.__file__
                    for sym_name, obj in inspect.getmembers(mod):
                        data = ChooserData(mod_name, sym_name, file_name)
                        if inspect.isfunction(obj):
                            data.sym_type = "function"
                            data.line_no = "%d" % obj.__code__.co_firstlineno
                            data.doc_str = inspect.getdoc(obj)
                        elif inspect.isclass(obj):
                            data.sym_type = "class"
                            data.doc_str = inspect.getdoc(obj)
                        elif inspect.ismethod(obj):
                            data.sym_type = "method"
                            data.line_no = "%d" % obj.im_func.__code__.co_firstlineno
                            data.doc_str = inspect.getdoc(obj)
                        elif type(obj) == int:
                            data.sym_type = "int"
                            data.sym_value = "0x%x" % (obj)
                        elif type(obj) == str:
                            data.sym_type = "str"
                            data.sym_value = str(obj)
                        else:
                            ida_kernwin.msg("未知符号 %s - %s" % (type(obj), sym_name))
                            continue
                        self.items.append(data)
            else:
                continue

    def OnGetLine(self, n):
        d = self.items[n]
        data = [d.mod_name, d.sym_name, "%s"%d.doc_str, d.sym_type, d.sym_value, d.line_no]
        return data

    def OnGetIcon(self, n):
        return self.items[n].get_icon()

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        data = self.items[n]
        postfix = " (%s)" % data.mod_name if len(data.mod_name) else ""
        if not data.doc_str:
            ida_kernwin.msg("文档不存在 \"%s\"\n" % data.sym_name)
        else:
            f = DocstringViewer("%s%s" % (data.sym_name, postfix), data.doc_str)
            f.modal = False
            f.openform_flags = ida_kernwin.PluginForm.WOPN_TAB
            f, _ = f.Compile()
            f.Open()
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def OnEditLine(self, n):
        fn = self.items[n].file_name
        if fn:
            if fn.endswith(".pyc"):
                fn = fn[:-1]
            with open(fn) as fin:
                f = FileViewer("%s" % (os.path.basename(fn)), fin.read())
                f.modal = False
                f.openform_flags = ida_kernwin.PluginForm.WOPN_TAB
                f, _ = f.Compile()
                f.Open()
        return (ida_kernwin.Choose.NOTHING_CHANGED, )            
