# -*- coding: utf-8 -*-

from idaapi import *

from helper import name_to_addr
from hexraystool import query

def scan_cve_2019_3568():
    """
    在 libwhatsapp.so 中扫描 CVE-2019-3568
    """
    expr = lambda cf, e: (e.op is cit_if and
            e.cif.expr.op is cot_land and
            e.cif.expr.y.op is cot_eq and
            e.cif.expr.y.y.op is cot_num and
            e.cif.expr.y.y.numval() == 51200)

    locations = set(CodeRefsTo(name_to_addr("__aeabi_memcpy"), False))
    return query(expr, locations, do_print=True)

if __name__ == "__main__":
    print("扫描 CVE-2019-3568...")
    scan_cve_2019_3568()
