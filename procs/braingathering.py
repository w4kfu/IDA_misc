# processor for vm braingathering from hack.lu ctf 2k12

from idaapi import *

class DecodingError(Exception):
    pass

class BrainProcessor(processor_t):
    id = 0x0
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    psnames = ["brain"]
    plnames = ["brain VM CPU"]
    segreg_size = 0
    instruc_start = 0

    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB | AS_ASCIIC | AS_ASCIIZ,
        "uflag": 0,
        "name": "brain",
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
        "R0", "R1", "Rflags", "R3", "R4",
        "SP",
        # Virtual
        "CS", "DS"
    ]

    instruc = instrs = [
        { 'name': 'PUSH', 'feature': CF_USE1 },
        { 'name': 'NOP', 'feature': 0 },
        { 'name': 'POP', 'feature': CF_USE1 },
        { 'name': 'MOV', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'ADD', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'SUB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'OR', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'AND', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'XOR', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'TEST', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'CMP', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'CALL', 'feature': CF_USE1 | CF_CALL },
        { 'name': 'RET', 'feature': CF_STOP },
        { 'name': 'END', 'feature': CF_STOP },
        { 'name': 'JE', 'feature': CF_USE1 },
        { 'name': 'SYSCALL', 'feature': 0 },
        { 'name': 'TEST', 'feature': CF_USE1  | CF_USE2 },
        { 'name': 'SLEEP', 'feature': 0 },
        { 'name': 'WRITE', 'feature': CF_USE1  | CF_USE2 },
        { 'name': 'READ', 'feature': CF_USE1  | CF_USE2 },
        { 'name': 'OPEN', 'feature': CF_USE1},
        { 'name': 'CLOSE', 'feature': CF_USE1},

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

    def _ana(self):
        cmd = self.cmd

        opcode = self._read_cmd_byte()

        print "opcode = " + hex(opcode)
        if opcode == 0xFF:
            cmd.itype = self.inames["END"]
        elif opcode == 0xA:
            cmd.itype = self.inames["TEST"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 4
            cmd[1].type = o_reg
            cmd[1].dtype = dt_word
            cmd[1].reg = 3
        elif opcode == 0x0D:
            test = self._read_cmd_byte()
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 2
            if (test):
                cmd.itype = self.inames["OR"]
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_byte
                cmd[1].value = 0x10
            else:
                cmd.itype = self.inames["AND"]
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_byte
                cmd[1].value = 0xEF
        elif opcode == 0x14:
            cmd.itype = self.inames["PUSH"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 2
        elif opcode == 0x20:
            cmd.itype = self.inames["PUSH"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 4
        elif opcode == 0x27:
            cmd.itype = self.inames["CALL"]
            cmd[0].type = o_near
            cmd[0].dtype = dt_word
            addr = self._read_cmd_byte()
            addr |= self._read_cmd_byte() << 8
            cmd[0].addr = addr
        elif opcode == 0x21:
            cmd.itype = self.inames["MOV"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 4
            cmd[1].type = o_phrase
            cmd[1].dtyp = dt_word
            cmd[1].reg = 3
        elif opcode == 0x28:
            cmd.itype = self.inames["ADD"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 5
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x2C:
            cmd.itype = self.inames["TEST"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 4
            cmd[1].type = o_reg
            cmd[1].dtype = dt_word
            cmd[1].reg = 1
        elif opcode == 0x30: # [r4], r3
            cmd.itype = self.inames["MOV"]
            cmd[0].type = o_phrase
            cmd[0].dtype = dt_word
            cmd[0].reg = 4
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_word
            cmd[1].reg = 3
        elif opcode == 0x31:
            test = self._read_cmd_byte()
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 2
            if (test):
                cmd.itype = self.inames["OR"]
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_byte
                cmd[1].value = 0x20
            else:
                cmd.itype = self.inames["AND"]
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_byte
                cmd[1].value = 0xDF
        elif opcode == 0x33:
            cmd.itype = self.inames["MOV"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 3
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_word
            cmd[1].reg = 5
        elif opcode == 0x36:
            cmd.itype = self.inames["ADD"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 3
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x3D:
            cmd.itype = self.inames["SUB"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 5
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x3F:
            cmd.itype = self.inames["READ"]
            fd = self._read_cmd_byte()
            cmd[0].type = o_imm
            cmd[0].dtyp = dt_word
            cmd[0].value = fd
            cmd[1].type = o_reg
            cmd[1].dtype = dt_word
            cmd[1].reg = 5
        elif opcode == 0x40:
            cmd.itype = self.inames["WRITE"]
            fd = self._read_cmd_byte()
            if (fd > 1):
                fd = 2
            cmd[0].type = o_imm
            cmd[0].dtyp = dt_word
            cmd[0].value = fd
            cmd[1].type = o_reg
            cmd[1].dtype = dt_word
            cmd[1].reg = 4
        elif opcode == 0x41:
            cmd.itype = self.inames["POP"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 2
        elif opcode == 0x42:
            cmd.itype = self.inames["OPEN"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 4
        elif opcode == 0x43:
            cmd.itype = self.inames["CLOSE"]
        elif opcode == 0x45:
            cmd.itype = self.inames["ADD"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 1
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x47:
            cmd.itype = self.inames["JE"] # TO FIX
            addr = self._read_cmd_byte()
            addr |= self._read_cmd_byte() << 8
            cmd[0].type = o_near
            cmd[0].dtype = dt_word
            cmd[0].addr = addr
        elif opcode == 0x49:
            cmd.itype = self.inames["MOV"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 4
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x4B:
            cmd.itype = self.inames["MOV"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 1
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x4F:
            cmd.itype = self.inames["ADD"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 4
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x53:
            cmd.itype = self.inames["PUSH"]
            cmd[0].type = o_imm
            cmd[0].dtyp = dt_word
            cmd[0].value = self._read_cmd_byte()
            cmd[0].value |= self._read_cmd_byte() << 8
        elif opcode == 0x58:
            cmd.itype = self.inames["RET"]
        elif opcode == 0x5C:
            test = self._read_cmd_byte()
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 2
            if (test):
                cmd.itype = self.inames["OR"]
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_byte
                cmd[1].value = 0x20
            else:
                cmd.itype = self.inames["AND"]
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_byte
                cmd[1].value = 0xDF
        elif opcode == 0x61:
            cmd.itype = self.inames["XOR"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 4
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x66:
            cmd.itype = self.inames["MOV"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 3
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x68:
            cmd.itype = self.inames["POP"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 3
        elif opcode == 0x69:
            test = self._read_cmd_byte()
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 2
            if (test):
                cmd.itype = self.inames["OR"]
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_byte
                cmd[1].value = 0x40
            else:
                cmd.itype = self.inames["AND"]
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_byte
                cmd[1].value = 0xBF
        elif opcode == 0x71:
            cmd.itype = self.inames["PUSH"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 3
        elif opcode == 0x74:
            cmd.itype = self.inames["POP"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 4
        elif opcode == 0x79:
            cmd.itype = self.inames["SUB"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 1
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_word
            cmd[1].value = self._read_cmd_byte()
            cmd[1].value |= self._read_cmd_byte() << 8
        elif opcode == 0x81:
            cmd.itype = self.inames["MOV"]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_word
            cmd[0].reg = 4
            cmd[1].type = o_reg
            cmd[1].reg = 5
        elif opcode == 0x82:
            ## PUSH AND CHECK IF FAILED !!
            cmd.itype = self.inames["PUSH"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 1
        elif opcode == 0x86:
            cmd.itype = self.inames["POP"]
            cmd[0].type = o_reg
            cmd[0].dtype = dt_word
            cmd[0].reg = 1
        elif opcode == 0x90:
            cmd.itype = self.inames["SLEEP"]
        elif opcode == 0xA0 or opcode == 0x5A:
            cmd.itype = self.inames["NOP"]
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
    return BrainProcessor()
