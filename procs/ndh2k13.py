from idaapi import *

class DecodingError(Exception):
    pass

class NDHProcessor(processor_t):
    id = 0x8000 + 5855
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    psnames = ["ndh2k13"]
    plnames = ["ndh2k13 VM CPU"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB,
        "uflag": 0,
        "name": "NDH assembler",
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
        "R0", "R1", "R2", "R3", "R4",
        "R5", "R6", "R7", "SP", "BP",
        "CS", "DS"
    ]

    instruc = instrs = [
        { 'name': 'PUSH', 'feature': CF_USE1 },
        { 'name': 'PUSHB', 'feature': CF_USE1 },
        { 'name': 'PUSHW', 'feature': CF_USE1 },
        { 'name': 'NOP', 'feature': 0 },
        { 'name': 'POP', 'feature': CF_USE1 },
        { 'name': 'MOV', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'MOVB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'MOVW', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'ADD', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'ADDB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'ADDW', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'SUB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'SUBB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'SUBW', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'MUL', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'MULB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'MULW', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'DIV', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'DIVB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'DIVW', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'INC', 'feature': CF_USE1 },
        { 'name': 'DEC', 'feature': CF_USE1 },
        { 'name': 'OR', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'ORB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'ORW', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'AND', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'ANDB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'ANDW', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'XOR', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'XORB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'XORW', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'NOT', 'feature': CF_USE1 },
        { 'name': 'JZ', 'feature': CF_USE1 },
        { 'name': 'JNZ', 'feature': CF_USE1 },
        { 'name': 'JMPS', 'feature': CF_USE1 | CF_STOP },
        { 'name': 'TEST', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'CMP', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'CMPB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'CMPW', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'CALL', 'feature': CF_USE1 | CF_CALL },
        { 'name': 'RET', 'feature': CF_STOP },
        { 'name': 'JMPL', 'feature': CF_USE1 | CF_STOP },
        { 'name': 'END', 'feature': CF_STOP },
        { 'name': 'XCHG', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'JA', 'feature': CF_USE1 },
        { 'name': 'JB', 'feature': CF_USE1 },
        { 'name': 'SYSCALL', 'feature': 0 },
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

    def _ana_ntypeinstr(self, name, valid):
        cmd = self.cmd
        optype = self._read_cmd_byte()

        if optype not in valid:
            raise DecodingError()

        if optype not in (4, 5, 6):
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = self._read_reg()

        if optype == 0x0:
            cmd.itype = self.inames[name]
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_word
            cmd[1].reg = self._read_reg()
        elif optype == 0x1:
            cmd.itype = self.inames[name + "B"]
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_byte
            cmd[1].value = self._read_cmd_byte()
        elif optype == 0x2:
            cmd.itype = self.inames[name + "W"]
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif optype == 0x3:
            cmd.itype = self.inames[name]
        elif optype == 0x4:
            cmd.itype = self.inames[name + "B"]
            cmd[0].type = o_imm
            cmd[0].dtyp = dt_byte
            cmd[0].value = self._read_cmd_byte()
        elif optype == 0x5:
            cmd.itype = self.inames[name + "W"]
            cmd[0].type = o_imm
            cmd[0].dtyp = dt_word
            cmd[0].value = self._read_cmd_byte()
            cmd[0].value |= self._read_cmd_byte() << 8
        elif optype == 0x6:
            cmd.itype = self.inames[name + "B"]
            cmd[0].type = o_phrase
            cmd[0].dtyp = dt_word
            cmd[0].reg = self._read_reg()
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_word
            cmd[1].reg = self._read_reg()
        elif optype == 0xA:
            cmd.itype = self.inames[name]
            cmd[1].type = o_phrase
            cmd[1].dtyp = dt_word
            cmd[1].reg = self._read_reg()
        else:
            raise DecodingError()

    def _ana_one_r(self, name):
        cmd = self.cmd
        cmd.itype = self.inames[name]
        cmd[0].type = o_reg
        cmd[0].dtyp = dt_word
        cmd[0].reg = self._read_reg()

    def _ana_two_r(self, name):
        cmd = self.cmd
        cmd.itype = self.inames[name]
        cmd[0].type = o_reg
        cmd[0].dtyp = dt_word
        cmd[0].reg = self._read_reg()
        cmd[1].type = o_reg
        cmd[1].dtyp = dt_word
        cmd[1].reg = self._read_reg()

    def _ana_jmp(self, name, size=16):
        cmd = self.cmd
        cmd.itype = self.inames[name]
        addr = self._read_cmd_byte()
        if size == 16:
            addr |= self._read_cmd_byte() << 8
            if (addr & 0x8000):
                addr -= 0x10000
        else:
            if addr & 0x80:
                addr -= 0x100
        addr += cmd.ea + cmd.size
        cmd[0].type = o_near
        cmd[0].dtyp = dt_word
        cmd[0].addr = addr

    def _ana(self):
        cmd = self.cmd
        opcode = self._read_cmd_byte()
        if opcode == 0x1F:
            self._ana_ntypeinstr("PUSH", valid=(3, 4, 5))
        elif opcode == 0x0A:
            cmd.itype = self.inames["JMPL"]
            self._ana_jmp("JMPL")
        elif opcode == 0x1C:
            self._ana_ntypeinstr("MOV", valid=(0, 1, 2, 6, 7, 8, 9, 10))
        elif opcode == 0x0C:
            cmd.itype = self.inames["CALL"]
            flags = self._read_cmd_byte()
            if flags == 0x4:
                addr = self._read_cmd_byte()
                addr |= self._read_cmd_byte() << 8
                if (addr & 0x8000):
                    addr -= 0x10000
                addr += cmd.ea + cmd.size
                cmd[0].type = o_near
                cmd[0].dtyp = dt_word
                cmd[0].addr = addr
            elif flags == 0x3:
                reg = self._read_reg()
                cmd[0].type = o_reg
                cmd[0].dtyp = dt_word
                cmd[0].reg = reg
            else:
                raise DecodingError()
        elif opcode == 0x30:
            cmd.itype = self.inames["SYSCALL"]
        elif opcode == 0x0B:
            cmd.itype = self.inames["RET"]
        elif opcode == 0x1A:
            self._ana_ntypeinstr("SUB", valid=(0, 1, 2))
        elif opcode == 0x0D:
            self._ana_ntypeinstr("CMP", valid=(0, 1, 2))
        elif opcode == 0x11:
            self._ana_jmp("JZ")
        elif opcode == 0x09:
            cmd.itype = self.inames["END"]
        elif opcode == 0x1F:
            self._ana_jmp("JMPS", size=8)
        elif opcode == 0x17:
            self._ana_one_r("INC")
        elif opcode == 0x10:
            self._ana_jmp("JNZ")
        elif opcode == 0x16:
            self._ana_one_r("DEC")
        elif opcode == 0x13:
            self._ana_ntypeinstr("XOR", valid=(0, 1, 2))
        elif opcode == 0x0E:
            self._ana_two_r("TEST")
        elif opcode == 0x1D:
            self._ana_one_r("POP")
        elif opcode == 0x07:
            self._ana_jmp("JA")
        elif opcode == 0x0F:
            self._ana_jmp("JMPS", size=8)
        elif opcode == 0x06:
            self._ana_jmp("JB")
        elif opcode == 0x1B:
            self._ana_ntypeinstr("ADD", valid=(0, 1, 2))
        elif opcode == 0x08:
            self._ana_two_r("XCHG")
        elif opcode == 0x19:
            self._ana_ntypeinstr("MUL", valid=(0, 1, 2))
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
    return NDHProcessor()