from idaapi import *

class DecodingError(Exception):
    pass

class FuelVMProcessor(processor_t):
    id = 0x4343
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    psnames = ["FuelVM"]
    plnames = ["FuelVM"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB,
        "uflag": 0,
        "name": "FuelVM assembler",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = [
        "R1", "R2", "R3", "R4", "SP", "PC",
        "CS", "DS"
    ]

    instruc = instrs = [
        { 'name': 'PUSH', 'feature': CF_USE1 },
        { 'name': 'POP', 'feature': CF_USE1 },
        { 'name': 'CMP', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'MOV', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'INC', 'feature': CF_USE1 },
        { 'name': 'DEC', 'feature': CF_USE1 },
        { 'name': 'AND', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'OR', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'XOR', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'JMP', 'feature': CF_USE1 | CF_STOP },
        { 'name': 'JZ', 'feature': CF_USE1 },
        { 'name': 'JG', 'feature': CF_USE1 },
        { 'name': 'JB', 'feature': CF_USE1 },
        { 'name': 'END', 'feature': CF_STOP }
    ]
    instruc_end = len(instruc)

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["DS"]

    def _read_cmd_byte(self):
        ea = self.cmd.ea + self.cmd.size
        byte = get_full_byte(ea)
        self.cmd.size += 1
        return byte

    def _read_reg(self):
        r = self._read_cmd_byte()
        if r >= 0x0A:
            raise DecodingError()
        return r

    def _ana_one(self, name, valid):
        cmd = self.cmd
        optype = self._read_cmd_byte()

        if optype not in valid:
            raise DecodingError()

        if optype in (1, 2, 3, 4):
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = optype - 1
        elif optype == 0x5:
            cmd[0].type = o_imm
            cmd[0].dtyp = dt_word
            cmd[0].value = self._read_cmd_byte()
            cmd[0].value |= self._read_cmd_byte() << 8
        else:
            raise DecodingError()

    def _ana_mov(self, name, valid):
        cmd = self.cmd
        optype = self._read_cmd_byte()

        if optype not in valid:
            raise DecodingError()

        if optype in (1, 2, 3, 6):
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 0
            if optype in (1, 2, 3):
                cmd[1].type = o_reg
                cmd[1].dtyp = dt_word
                cmd[1].reg = optype
            else:
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_word
                cmd[1].value = self._read_cmd_byte()
                cmd[1].value |= self._read_cmd_byte() << 8
        elif optype == 7:
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 1
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif optype == 8:
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 2
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        else:
            raise DecodingError()

    def _ana_cmp(self, name, valid):
        cmd = self.cmd
        optype = self._read_cmd_byte()

        if optype not in valid:
            raise DecodingError()
        if optype in (1, 2):
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 0
        else:
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = optype - 1
        if optype in(2, 3, 4, 5):
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        else:
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 1

    def _ana(self):
        cmd = self.cmd
        opcode = self._read_cmd_byte()
        if opcode == 0x0A:
            cmd.itype = self.inames["PUSH"]
            self._ana_one("PUSH", valid=(1, 2, 3, 4, 5))
        elif opcode == 0x0B:
            cmd.itype = self.inames["POP"]
            self._ana_one("POP", valid=(1, 2, 3, 4))
        elif opcode == 0x0C:
            cmd.itype = self.inames["MOV"]
            self._ana_mov("MOV", valid=(1, 2, 3, 6, 7, 8))
        elif opcode == 0x1C:
            cmd.itype = self.inames["OR"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = self._read_reg() - 1
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x0D:
            cmd.itype = self.inames["CMP"]
            self._ana_cmp("CMP", valid=(1, 2, 3, 5))
        elif opcode == 0x0E:
            cmd.itype = self.inames["INC"]
            self._ana_one("INC", valid=(1, 2, 3, 4, 5))
        elif opcode == 0x0F:
            cmd.itype = self.inames["DEC"]
            self._ana_one("DEC", valid=(1, 2, 3, 4, 5))
        elif opcode == 0x1B:
            cmd.itype = self.inames["AND"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = self._read_reg() - 1
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0xFF:
            cmd.itype = self.inames["END"]
        else:
            raise DecodingError()
        return cmd.size

    def ana(self):
        try:
            return self._ana()
        except DecodingError:
            return 0

    def _emu_operand(self, op):
        if op.type == o_mem:
            ua_dodata2(0, op.addr, op.dtyp)
            ua_add_dref(0, op.addr, dr_R)
        elif op.type == o_near:
            if self.cmd.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            ua_add_cref(0, op.addr, fl)

    def emu(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        if ft & CF_USE1:
            self._emu_operand(cmd[0])
        if ft & CF_USE2:
            self._emu_operand(cmd[1])
        if ft & CF_USE3:
            self._emu_operand(cmd[2])
        if not ft & CF_STOP:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)
        return True

    def outop(self, op):
        if op.type == o_reg:
            out_register(self.reg_names[op.reg])
        elif op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type in [o_near, o_mem]:
            ok = out_name_expr(op, op.addr, BADADDR)
            if not ok:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueMark(Q_noName, self.cmd.ea)
        elif op.type == o_phrase:
            out_symbol('[')
            out_register(self.reg_names[op.reg])
            out_symbol(']')
        else:
            return False
        return True

    def out(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        buf = init_output_buffer(1024)
        OutMnem(15)
        if ft & CF_USE1:
            out_one_operand(0)
        if ft & CF_USE2:
            OutChar(',')
            OutChar(' ')
            out_one_operand(1)
        if ft & CF_USE3:
            OutChar(',')
            OutChar(' ')
            out_one_operand(2)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)

def PROCESSOR_ENTRY():
    return FuelVMProcessor()