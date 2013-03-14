from idaapi import *

class DecodingError(Exception):
    pass

class Instr(object):
    def __init__(self, name, opcode, nb_arg, flag):
        self.name = name
        self.opcode = opcode
        self.nb_arg = nb_arg
        self.flags = flag

class antofikProcessor(processor_t):
    id = 0x4242
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    psnames = ["antofik"]
    plnames = ["antofik VM CPU"]
    w = "w"
    b = "b"
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB,
        "uflag": 0,
        "name": "antofik assembler",
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

    opcodes = [
    ["", 0, 0],
    ["add", 2, CF_USE1 | CF_USE2],
    ["sub", 2, CF_USE1 | CF_USE2],
	["mul", 1, CF_USE1],
	["div", 1, CF_USE1],
	["xor", 2, CF_USE1 | CF_USE2],
	["or", 2, CF_USE1 | CF_USE2],
	["and", 2, CF_USE1 | CF_USE2],
	["push", 1, CF_USE1],
	["pop", 1, CF_USE1],
	["shl", 2, CF_USE1 | CF_USE2],
	["shr", 2, CF_USE1 | CF_USE2],
	["inc", 1, CF_USE1],
	["dec", 1, CF_USE1],
	["", 0, 0],
	["", 0, 0],
    ["mov", 2, CF_USE1 | CF_USE2],
	["nop", 0, 0],
	["", 0, 0],
	["", 0, 0],
	["call", 1, CF_USE1],
	["ret", 0, CF_STOP],
	["nop", 0, 0],
	["", 0, 0],
	["cmp", 2, CF_USE1 | CF_USE2],
	["", 0, 0],
	["jmp", 1, CF_USE1],
	["je", 1, CF_USE1],
	["ja", 1, CF_USE1],
	["jae", 1, CF_USE1],
	]

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.instrs_opcode = [None] * len(self.opcodes)
        self.instrs_list = []

        opcode = 0
        for op in self.opcodes:
            instr = Instr(op[0], opcode, op[1], op[2])
            self.instrs_opcode[opcode] = instr
            opcode = opcode + 1

        self.instruc = [{ "name": i.name, "feature": i.flags }
                        for i in self.instrs_opcode]
        self.instruc_end = len(self.instruc)

        self.instrs = {}
        for instr in self.instrs_opcode:
            self.instrs[instr.name] = instr

        self.instrs_ids = {}
        for i, instr in enumerate(self.instrs_opcode):
            self.instrs_ids[instr.name] = i
            instr.id = i

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

    def _ana_dest(self, instr):
        cmd = self.cmd
        cmd.itype = instr.id
        addr = self._read_cmd_byte() << 8
        addr |= self._read_cmd_byte()
        addr += cmd.ea + cmd.size
        cmd[0].type = o_near
        cmd[0].dtyp = dt_word
        cmd[0].addr = (addr & 0xFFFF)

    def _ana_one(self, instr, byte1):
        cmd = self.cmd
        cmd.itype = instr.id
        bx = (byte1 & 0x6) >> 1
        if bx == 0:
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = self._read_reg()
        elif bx == 1:
            if instr.name.startswith("j") or instr.name.startswith("call"):
                self._ana_dest(instr)
            else:
                cmd[0].type = o_imm
                cmd[0].dtyp = dt_word
                cmd[0].value = self._read_cmd_byte() << 8
                cmd[0].value |= self._read_cmd_byte()
        elif bx == 2:
            cmd[0].type = o_phrase
            cmd[0].dtyp = dt_word
            cmd[0].reg = self._read_reg()
        elif bx == 3:
            cmd[0].type = o_phrase
            cmd[0].dtyp = dt_word
            cmd[0].reg = 42
            cmd[0].value = self._read_cmd_byte() << 8
            cmd[0].value |= self._read_cmd_byte()
        else:
            raise DecodingError()

    def _ana_two(self, instr, byte1):
        cmd = self.cmd
        cmd.itype = instr.id
        bxh = (byte1 & 0x6) >> 1
        bxl = (byte1 & 0x1)
        if bxh != 1 and bxh != 3:
            if bxh == 0:
                cmd[1].type = o_reg
                cmd[1].dtyp = dt_word
                cmd[1].reg = self._read_reg()
            elif bxh == 2:
                cmd[1].type = o_phrase
                cmd[1].dtyp = dt_word
                cmd[1].reg = self._read_reg()
            else:
                raise DecodingError()
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = self._read_reg()
        else:
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte() << 8
            cmd[1].value |= self._read_cmd_byte()
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = self._read_reg()

    def ana(self):
        cmd = self.cmd
        byte1 = self._read_cmd_byte()
        instr = self.instrs_opcode[(byte1 & 0xF8) >> 3]
        if instr is None:
            return 0
        if instr.nb_arg == 1:
            self._ana_one(instr, byte1)
        elif instr.nb_arg == 2:
            self._ana_two(instr, byte1)
        else:
            cmd.itype = instr.id
        return cmd.size

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
            if op.reg == 42:
                OutValue(op, OOFW_IMM)
            else:
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
    return antofikProcessor()