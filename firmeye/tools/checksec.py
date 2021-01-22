# -*- coding: utf-8 -*-

import lief


class Checksec():
    """
    检查 ELF 的保护机制
    """

    def __init__(self, elfpath):
        self.path = elfpath
        self.binary = lief.parse(elfpath)

        self.sec = {
            "RELRO": {
                'Full': "Full RELRO",
                'Partial': "Partial RELRO",
                None: "No RELRO"
            }[self.check_relro],
            "Canary": {
                True: "Canary found",
                False: "No canary found"
            }[self.check_canary],
            "NX": {
                True: "NX enabled",
                False: "NX disabled"
            }[self.check_nx],
            "PIE": {
                True: "PIE enabled",
                False: "No PIE (%#x)" % self.binary.header.entrypoint
            }[self.check_pie],
            "FORTIFY": {
                True: "FORTIRY enabled",
                False: "FORTIRY disabled"
            }[self.check_fortify],
        }

    @property
    def check_relro(self):
        """
        ELF Specification: https://refspecs.linuxbase.org/elf/elf.pdf
        page 81: https://refspecs.linuxbase.org/elf/elf.pdf#page=81
        DT_BIND_NOW: https://refspecs.linuxbase.org/elf/elf.pdf#page=81
        PT_GNU_RELRO: https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic.html#PROGHEADER
        DF_BIND_NOW: http://refspecs.linuxbase.org/elf/gabi4+/ch5.dynamic.html#df_bind_now
        """
        if not any('GNU_RELRO' in str(s.type) for s in self.binary.segments):
            return None

        dynamic = self.binary.get_section('.dynamic')
        if dynamic:
            for entry in self.binary.dynamic_entries:
                if entry.tag == lief.ELF.DYNAMIC_TAGS.FLAGS \
                            and entry.value == lief.ELF.DYNAMIC_FLAGS.BIND_NOW.__int__():
                    return "Full"

        return "Partial"

    @property
    def check_canary(self):
        if self.binary.has_symbol('__stack_chk_fail'):
            return True
    
        for r in self.binary.pltgot_relocations:
            if r.symbol.name == '__stack_chk_fail':
                return True

        return False

    @property
    def check_pie(self):
        return self.binary.is_pie

    @property
    def check_nx(self):
        """
        https://github.com/torvalds/linux/blob/v4.9/fs/binfmt_elf.c#L784-L789
        https://github.com/torvalds/linux/blob/v4.9/fs/binfmt_elf.c#L849-L850
        """
        #if self.binary.header.file_type != lief.ELF.E_TYPE.EXECUTABLE:
        #    return True
        for s in self.binary.segments:
            if "GNU_STACK" in str(s.type):
                if s.has(lief.ELF.SEGMENT_FLAGS.X):
                    return False

        return True

    @property
    def check_fortify(self):
        for r in self.binary.pltgot_relocations:
            if r.symbol.name.endswith == '_chk':
                return True

        return False
