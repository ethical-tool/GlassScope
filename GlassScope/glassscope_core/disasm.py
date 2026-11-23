"""Pure-Python disassembler for x86, x86-64 and ARM64 (AArch64) machine code
with no external dependencies.

The x86/x64 decoder interprets the dominant instruction subset: one-byte
opcodes, the common two-byte 0F page (SSE moves, compares, logic), full
ModRM/SIB/displacement/immediate decoding for all addressing modes, and
prefix handling (operand/address size, REX, lock/rep). The ARM64 decoder
covers the common A64 classes (ADD/SUB, MOV/MOVZ/MOVK/MOVN, LDR/STR/LDP/STP,
B/BL/BLR/BR/RET, ADRP, logical ops, NOP, SVC) with operand formatting. The
aim is recognizing routines, entry stubs and packer code rather than
cycle perfection — good enough for triage, pattern matching and
entropy-gated code walks inside GlassScope.

Everything is bounded and defensive; garbage input yields `unknown` rows
rather than crashes.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# x86 / x86-64 tables
# ---------------------------------------------------------------------------

_X86_ONE = {
    0x00: ("add", "rm8, r8"), 0x01: ("add", "rm{l}, r{l}"),
    0x02: ("add", "r8, rm8"), 0x03: ("add", "r{l}, rm{l}"),
    0x04: ("add", "al, imm8"), 0x05: ("add", "a, imm{z}"),
    0x08: ("or", "rm8, r8"), 0x09: ("or", "rm{l}, r{l}"),
    0x0A: ("or", "r8, rm8"), 0x0B: ("or", "r{l}, rm{l}"),
    0x0C: ("or", "al, imm8"), 0x0D: ("or", "a, imm{z}"),
    0x10: ("adc", "rm8, r8"), 0x11: ("adc", "rm{l}, r{l}"),
    0x12: ("adc", "r8, rm8"), 0x13: ("adc", "r{l}, rm{l}"),
    0x14: ("adc", "al, imm8"), 0x15: ("adc", "a, imm{z}"),
    0x18: ("sbb", "rm8, r8"), 0x19: ("sbb", "rm{l}, r{l}"),
    0x1A: ("sbb", "r8, rm8"), 0x1B: ("sbb", "r{l}, rm{l}"),
    0x1C: ("sbb", "al, imm8"), 0x1D: ("sbb", "a, imm{z}"),
    0x20: ("and", "rm8, r8"), 0x21: ("and", "rm{l}, r{l}"),
    0x22: ("and", "r8, rm8"), 0x23: ("and", "r{l}, rm{l}"),
    0x24: ("and", "al, imm8"), 0x25: ("and", "a, imm{z}"),
    0x28: ("sub", "rm8, r8"), 0x29: ("sub", "rm{l}, r{l}"),
    0x2A: ("sub", "r8, rm8"), 0x2B: ("sub", "r{l}, rm{l}"),
    0x2C: ("sub", "al, imm8"), 0x2D: ("sub", "a, imm{z}"),
    0x30: ("xor", "rm8, r8"), 0x31: ("xor", "rm{l}, r{l}"),
    0x32: ("xor", "r8, rm8"), 0x33: ("xor", "r{l}, rm{l}"),
    0x34: ("xor", "al, imm8"), 0x35: ("xor", "a, imm{z}"),
    0x38: ("cmp", "rm8, r8"), 0x39: ("cmp", "rm{l}, r{l}"),
    0x3A: ("cmp", "r8, rm8"), 0x3B: ("cmp", "r{l}, rm{l}"),
    0x3C: ("cmp", "al, imm8"), 0x3D: ("cmp", "a, imm{z}"),
}
for _i, _mn in ((0x50, "push"), (0x58, "pop")):
    for _k in range(8):
        _X86_ONE[_i + _k] = (_mn, "reg50_57" if _i == 0x50 else "reg58_5f")
for _i in range(0x70, 0x80):
    _JCC8 = ("jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
             "jp", "jnp", "jl", "jge", "jle", "jg")
    _X86_ONE[0x70 + _i - 0x70] = (_JCC8[_i - 0x70], "rel8")
_X86_ONE.update({
    0x80: ("grp1", "rm8, imm8"), 0x81: ("grp1", "rm{l}, imm{z}"),
    0x83: ("grp1", "rm{l}, imm8s"),
    0x84: ("test", "rm8, r8"), 0x85: ("test", "rm{l}, r{l}"),
    0x86: ("xchg", "rm8, r8"), 0x87: ("xchg", "rm{l}, r{l}"),
    0x88: ("mov", "rm8, r8"), 0x89: ("mov", "rm{l}, r{l}"),
    0x8A: ("mov", "r8, rm8"), 0x8B: ("mov", "r{l}, rm{l}"),
    0x8D: ("lea", "r{l}, rm"), 0x8F: ("pop", "rm{l}"),
    0x63: ("movsxd", "r64, rm32"),
    0x90: ("nop", ""), 0x98: ("cwde", ""), 0x99: ("cdq", ""),
    0x9C: ("pushf", ""), 0x9D: ("popf", ""),
    0xA4: ("movsb", ""), 0xA5: ("movsd", ""),
    0xA6: ("cmpsb", ""), 0xA7: ("cmpsd", ""),
    0xAA: ("stosb", ""), 0xAB: ("stosd", ""),
    0xAC: ("lodsb", ""), 0xAD: ("lodsd", ""),
    0xA8: ("test", "al, imm8"), 0xA9: ("test", "a, imm{z}"),
    0xC0: ("grp2", "rm8, imm8"), 0xC1: ("grp2", "rm{l}, imm8"),
    0xC2: ("ret", "imm16"), 0xC3: ("ret", ""),
    0xCA: ("retf", "imm16"), 0xCB: ("retf", ""),
    0xC6: ("mov", "rm8, imm8"), 0xC7: ("mov", "rm{l}, imm{z}"),
    0xC9: ("leave", ""), 0xCC: ("int3", ""), 0xCD: ("int", "imm8"),
    0xD0: ("grp2", "rm8, one"), 0xD1: ("grp2", "rm{l}, one"),
    0xD2: ("grp2", "rm8, cl"), 0xD3: ("grp2", "rm{l}, cl"),
    0xE3: ("jxczx", "rel8"),
    0xE8: ("call", "rel32"), 0xE9: ("jmp", "rel32"), 0xEB: ("jmp", "rel8"),
    0xF4: ("hlt", ""), 0xF5: ("cmc", ""), 0xF8: ("clc", ""),
    0xF9: ("stc", ""), 0xFA: ("cli", ""), 0xFB: ("sti", ""),
    0xFC: ("cld", ""), 0xFD: ("std", ""),
    0xF6: ("grp3", "rm8"), 0xF7: ("grp3", "rm{l}"),
    0xFE: ("grp4", "rm8"), 0xFF: ("grp5", "rm{l}"),
})
# mov reg, imm (B0-BF) and mov r32, imm32 (B8-BF) handled specially below
for _k in range(8):
    _X86_ONE[0xB0 + _k] = ("mov", "reg8imm")
for _k in range(8):
    _X86_ONE[0xB8 + _k] = ("mov", "reglimm")

_X86_TWO = {
    0x05: ("syscall", ""), 0x0B: ("ud2", ""),
    0x1E: ("endbr64", ""), 0x1F: ("nopd", "rm"),
    0x90: ("seto", "rm8"), 0x91: ("setno", "rm8"),
    0x94: ("sete", "rm8"), 0x95: ("setne", "rm8"),
    0xA2: ("cpuid", ""),
    0xA3: ("bt", "rm{l}, r{l}"), 0xAB: ("bts", "rm{l}, r{l}"),
    0xAF: ("imul", "r{l}, rm{l}"),
    0xB6: ("movzx", "r{l}, rm8"), 0xB7: ("movzx", "r{l}, rm16"),
    0xBE: ("movsx", "r{l}, rm8"), 0xBF: ("movsx", "r{l}, rm16"),
    0x10: ("movups", "xmm, rm128"), 0x11: ("movups", "rm128, xmm"),
    0x28: ("movaps", "xmm, rm128"), 0x29: ("movaps", "rm128, xmm"),
    0x2E: ("ucomiss", "xmm, rm32"), 0x2F: ("comiss", "xmm, rm32"),
    0x51: ("sqrtsd", "xmm, rm64"), 0x54: ("andps", "xmm, rm128"),
    0x56: ("orps", "xmm, rm128"), 0x57: ("xorps", "xmm, rm128"),
    0x58: ("addps", "xmm, rm128"), 0x59: ("mulps", "xmm, rm128"),
    0x5C: ("subps", "xmm, rm128"), 0x5E: ("divps", "xmm, rm128"),
    0x6E: ("movd", "xmm, rm32"), 0x7E: ("movd", "rm32, xmm"),
    0x6F: ("movdqa", "xmm, rm128"), 0x7F: ("movdqa", "rm128, xmm"),
    0xEF: ("pxor", "xmm, rm128"),
}
_JCC32 = ("jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
          "jp", "jnp", "jl", "jge", "jle", "jg")
for _i in range(16):
    _X86_TWO[0x80 + _i] = (_JCC32[_i], "rel32")

_GROUPS = {
    "grp1": {0: "add", 1: "or", 2: "adc", 3: "sbb", 4: "and", 5: "sub",
             6: "xor", 7: "cmp"},
    "grp2": {0: "rol", 1: "ror", 2: "rcl", 3: "rcr", 4: "shl", 5: "shr",
             6: "sal", 7: "sar"},
    "grp3": {0: "test", 1: "test", 2: "not", 3: "neg", 4: "mul", 5: "imul",
             6: "div", 7: "idiv"},
    "grp4": {0: "inc", 1: "dec"},
    "grp5": {0: "inc", 1: "dec", 2: "call", 4: "jmp", 5: "push", 6: "pusha"},
}

REGS64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
REGS32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
          "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d")
REGS16 = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
          "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w")
REGS8 = ("al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
         "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b")
REGS8H = ("ah", "ch", "dh", "bh")


class _X86Dec:
    """Streaming decoder for one buffer of x86/x64 code."""

    def __init__(self, data: bytes, bitness: int = 64, base: int = 0):
        self.d = data
        self.pos = 0
        self.bitness = bitness
        self.base = base

    def u8(self) -> int | None:
        if self.pos >= len(self.d):
            return None
        v = self.d[self.pos]
        self.pos += 1
        return v

    def peek8(self) -> int | None:
        return self.d[self.pos] if self.pos < len(self.d) else None

    def u(self, n: int) -> int | None:
        if self.pos + n > len(self.d):
            return None
        v = int.from_bytes(self.d[self.pos:self.pos + n], "little")
        self.pos += n
        return v

    def reg(self, num: int, size: int) -> str:
        if size == 8:
            if num < 4 or (num < 8 and self.bitness != 64):
                return REGS8[num & 7]
            if num >= 8:
                return REGS8[num]
            return REGS8[num]  # spl/bpl/sil/dil under REX in 64-bit
        if size == 16:
            return REGS16[num]
        if size == 32:
            return REGS32[num]
        return REGS64[num]

    def modrm(self, size: int, rex: int) -> tuple[str, int] | None:
        """Decode modrm (+sib/disp). Return (rm_text, reg_field)."""
        m = self.u8()
        if m is None:
            return None
        mod = (m >> 6) & 3
        reg = ((m >> 3) & 7) | ((rex & 4) << 1 if rex else 0)
        rm = (m & 7) | ((rex & 1) << 3 if rex else 0)
        if mod == 3:
            return (self.reg(rm, size), reg)
        if self.bitness == 64:
            if (m & 7) == 4:  # SIB
                sib = self.u8()
                if sib is None:
                    return None
                scale = 1 << ((sib >> 6) & 3)
                idx = ((sib >> 3) & 7) | ((rex & 2) << 2 if rex else 0)
                base = (sib & 7) | ((rex & 1) << 3 if rex else 0)
                parts: list[str] = []
                if (sib & 7) == 5 and mod == 0:  # disp32, no base
                    disp = self.u(4)
                    if disp is None:
                        return None
                    if disp >= 0x80000000:
                        disp -= 1 << 32
                    parts.append(f"0x{disp & 0xFFFFFFFF:x}")
                else:
                    parts.append(REGS64[base])
                if idx != 4:  # rsp cannot be an index
                    parts.append(f"+{REGS64[idx]}*{scale}")
                if mod == 1:
                    disp = self.u(1)
                    if disp is None:
                        return None
                    if disp > 127:
                        disp -= 256
                    if disp:
                        parts.append(f"{disp:+#x}")
                elif mod == 2:
                    disp = self.u(4)
                    if disp is None:
                        return None
                    if disp >= 0x80000000:
                        disp -= 1 << 32
                    parts.append(f"{disp:+#x}")
                return (f"[{''.join(parts)}]", reg)
            if mod == 0 and (m & 7) == 5:  # RIP-relative
                disp = self.u(4)
                if disp is None:
                    return None
                d = disp - (1 << 32) if disp >= 0x80000000 else disp
                return (f"[rip{d:+#x}]", reg)
        if mod == 0 and (m & 7) == 5 and self.bitness != 64:
            disp = self.u(4)
            return (f"[{disp:#x}]" if disp is not None else None, reg)
        if mod == 0 and (m & 7) == 6 and self.bitness != 64:
            disp = self.u(2)
            return (f"[{disp:#x}]" if disp is not None else None, reg)
        bases = REGS64 if self.bitness == 64 else REGS32
        mem = bases[rm]
        if mod == 1:
            disp = self.u(1)
            if disp is None:
                return None
            if disp > 127:
                disp -= 256
            mem = f"[{mem}{disp:+#x}]"
        elif mod == 2:
            disp = self.u(4)
            if disp is None:
                return None
            if disp >= 0x80000000:
                disp -= 1 << 32
            mem = f"[{mem}{disp:+#x}]"
        else:
            mem = f"[{mem}]"
        return (mem, reg)

    def step(self) -> dict | None:
        start = self.pos
        prefixes: list[int] = []
        rex = 0
        opsize = 32
        op64 = False
        rep = None
        while True:
            b = self.u8()
            if b is None:
                return None
            if b == 0x66:
                prefixes.append(b)
                opsize = 16
            elif b == 0x67:
                prefixes.append(b)
            elif b in (0xF0,):
                prefixes.append(b)
            elif b in (0xF2, 0xF3):
                rep = b
                prefixes.append(b)
            elif b in (0x2E, 0x36, 0x26, 0x3E, 0x64, 0x65):
                prefixes.append(b)
            elif self.bitness == 64 and 0x40 <= b <= 0x4F:
                rex = b
                if b & 8:
                    op64 = True
                    opsize = 64
            else:
                break
        opcode = b
        if opcode == 0x0F:  # two-byte opcode
            b2 = self.u8()
            if b2 is None:
                return None
            if b2 == 0x38:  # three-byte (F3 0F 38 ...) — treat as opaque
                b3 = self.u8()
                if b3 is None:
                    return None
                return {"offset": start, "length": self.pos - start,
                        "text": f"0f 38 {b3:02x} (ssse3+)", "mnemonic":
                        "unknown"}
            spec = _X86_TWO.get(b2)
            if spec is None:
                return {"offset": start, "length": self.pos - start,
                        "text": f"0f {b2:02x}", "mnemonic": "unknown"}
            mnem, ops = spec
            size = 128 if "xmm" in ops else (opsize if not op64 else 64)
            if ops == "rel32":
                v = self.u(4)
                if v is None:
                    return None
                if v >= 0x80000000:
                    v -= 1 << 32
                target = self.base + self.pos + v
                text = f"{mnem} {target:#x}"
            else:
                text = self._render(mnem, ops, opcode, rex, opsize,
                                    start, size, b2)
            return {"offset": start, "length": self.pos - start,
                    "text": text, "mnemonic": mnem}
        # ---- one-byte opcode ------------------------------------------------
        spec = _X86_ONE.get(opcode)
        if spec is None:
            return {"offset": start, "length": self.pos - start,
                    "text": f"{opcode:02x}", "mnemonic": "unknown"}
        mnem, ops = spec
        if mnem in _GROUPS:  # group opcodes: real mnemonic from modrm reg
            # decode modrm once here; store for _render to reuse
            save = self.pos
            mv = self.modrm(8 if "rm8" in ops else opsize, rex)
            self.pos = save
            if mv is None:
                return None
            mnem = _GROUPS[mnem].get(mv[1] & 7, mnem)
            self._group_reg = mv[1] & 7
            if mnem == "pusha" or mnem == "push":
                mnem = "push"
        # fix stack regs for push/pop r64 in 64-bit
        if opcode in range(0x50, 0x60) and self.bitness == 64:
            mnem = "push"
        if opcode in range(0x58, 0x60) and self.bitness == 64:
            mnem = "pop"
        size = 64 if (self.bitness == 64 and not 0x66 in prefixes) else \
            (16 if 0x66 in prefixes else 32)
        text = self._render(mnem, ops, opcode, rex, opsize, start, size,
                            None)
        return {"offset": start, "length": self.pos - start, "text": text,
                "mnemonic": mnem}

    def _render(self, mnem: str, ops: str, opcode: int, rex: int, opsize: int,
                start: int, size: int, b2: int | None) -> str:
        if not ops:
            return mnem
        parts: list[str] = []
        # modrm decoded at most once per instruction; several templates
        # derive BOTH operands from it (rm + reg)
        mv: tuple[str, int] | None = None
        mv_done = False

        def modrm_once(msize: int) -> tuple[str, int] | None:
            nonlocal mv, mv_done
            if not mv_done:
                mv = self.modrm(msize, rex)
                mv_done = True
            return mv

        for o in ops.split(", "):
            if o in ("rm8",):
                t = modrm_once(8)
                if t is None:
                    return mnem + " <trunc>"
                parts.append(t[0])
            elif o in ("rm{l}", "rm", "rm16", "rm32", "rm64", "rm128"):
                t = modrm_once(size)
                if t is None:
                    return mnem + " <trunc>"
                parts.append(t[0])
            elif o == "r{l}" or o == "r64":
                t = modrm_once(size)
                if t is None:
                    return mnem + " <trunc>"
                parts.append(self.reg(t[1], size))
            elif o == "r8":
                t = modrm_once(8)
                if t is None:
                    return mnem + " <trunc>"
                parts.append(self.reg(t[1], 8))
            elif o == "rm8h":  # high-byte register operand
                t = modrm_once(8)
                if t is None:
                    return mnem + " <trunc>"
                parts.append(t[0])
            elif o in ("xmm",):
                t = modrm_once(size)
                if t is None:
                    return mnem + " <trunc>"
                parts.append(f"xmm{t[1] & 15}")
            elif o in ("xmmr", "rmxmm"):
                t = modrm_once(size)
                parts.append(t[0] if t else "?")
            elif o == "reg50_57" or o == "reg58_5f":
                parts.append(self.reg(opcode & 7, size))
            elif o == "reg8imm":
                parts.append(REGS8[opcode & 7])
            elif o == "reglimm":
                parts.append(self.reg(opcode & 7, size))
            elif o in ("imm8", "imm16", "imm32", "imm64", "imm{z}",
                       "imm8s"):
                n = {"imm8": 1, "imm8s": 1, "imm16": 2, "imm32": 4,
                     "imm64": 8, "imm{z}": 4 if opsize != 16 else 2}.get(o)
                v = self.u(n)
                if v is None:
                    return mnem + " <trunc>"
                if o == "imm8s" and v > 127:
                    v -= 256
                parts.append(f"0x{v:x}")
            elif o in ("rel8", "rel32"):
                n = 1 if o == "rel8" else 4
                v = self.u(n)
                if v is None:
                    return mnem + " <trunc>"
                if n == 1 and v > 127:
                    v -= 256
                if n == 4 and v >= 0x80000000:
                    v -= 1 << 32
                target = self.base + self.pos + v
                parts.append(f"{target:#x}")
            elif o == "a":
                parts.append(self.reg(0, size))
            elif o == "al":
                parts.append("al")
            elif o == "cl":
                parts.append("cl")
            elif o == "one":
                parts.append("1")
            elif o == "regimm":
                parts.append(self.reg(opcode & 7, size))
            else:
                parts.append(o)
        return mnem + (" " + ", ".join(parts) if parts else "")


def disassemble_x86(data: bytes, bitness: int = 64, base: int = 0,
                    limit: int = 4096) -> list[dict]:
    """Disassemble up to `limit` instructions. Returns rows of
    {offset, length, text, mnemonic}."""
    dec = _X86Dec(data, bitness=bitness, base=base)
    rows: list[dict] = []
    for _ in range(limit):
        try:
            row = dec.step()
        except (IndexError, ValueError):
            row = {"offset": dec.pos, "length": 1, "text": "?",
                   "mnemonic": "unknown"}
        if row is None:
            break
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# ARM64 / AArch64
# ---------------------------------------------------------------------------

_A64_64 = [f"x{i}" for i in range(31)] + ["sp"]
_A64_32 = [f"w{i}" for i in range(31)] + ["wsp"]


def _a64_reg(num: int, sf: bool) -> str:
    return (_A64_64 if sf else _A64_32)[num & 31]


def _a64_base(num: int, sf: bool = True) -> str:
    return "sp" if num == 31 else (_A64_64 if sf else _A64_32)[num & 31]


_A64_CONDS = ("eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls",
              "ge", "lt", "gt", "le", "al", "nv")


def _a64_one(insn: int, pc: int) -> tuple[str, str]:
    sf = bool(insn >> 31)
    Rd = insn & 31
    Rn = (insn >> 5) & 31
    Rm = (insn >> 16) & 31
    opc2 = (insn >> 29) & 7
    # --- unconditional branch B/BL -----------------------------------------
    if (insn >> 26) == 0x25:  # 100101 b imm26
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= 1 << 26
        mn = "bl" if (insn >> 31) else "b"
        return f"{mn} {pc + imm26 * 4:#x}", mn
    # --- B.cond (01010100 imm19 0 cond) ------------------------------------
    if (insn >> 24) == 0x54 and not (insn & (1 << 4)):
        cond = insn & 0xF
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= 1 << 19
        return f"b.{_A64_CONDS[cond]} {pc + imm19 * 4:#x}", "b.cond"
    # --- CBZ / CBNZ (x0011010 / x011010) ----------------------------------
    if (insn >> 24) in (0x34, 0xB4, 0x35, 0xB5, 0xF4, 0xF5):
        sf = bool(insn >> 31)
        op = (insn >> 24) & 1
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= 1 << 19
        mn = "cbnz" if op else "cbz"
        return f"{mn} {_a64_reg(insn & 31, sf)}, {pc + imm19 * 4:#x}", mn
    # --- TBZ / TBNZ ---------------------------------------------------------
    if (insn >> 24) in (0x36, 0x37, 0xB6, 0xB7):
        op = (insn >> 24) & 1
        b40 = (insn >> 19) & 0x1F
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & (1 << 13):
            imm14 -= 1 << 14
        mn = "tbnz" if op else "tbz"
        return (f"{mn} {_a64_reg(insn & 31, sf)}, #{b40}, "
                f"{pc + imm14 * 4:#x}"), mn
    # --- BLR / BR (1101011 0000 reg 00000) ---------------------------------
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        return f"blr {_a64_base(Rn)}", "blr"
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        return f"br {_a64_base(Rn)}", "br"
    # --- RET ------------------------------------------------------------------
    if insn == 0xD65F03C0:
        return "ret", "ret"
    if (insn & 0xFFFFFC1F) == 0xD65F0000:
        return f"ret {_a64_base(Rn)}", "ret"
    # --- ADRP / ADR ------------------------------------------------------------
    if (insn >> 24) & 0x9F == 0x90:
        rd = insn & 31
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= 1 << 33
        return f"adrp {_a64_reg(rd, True)}, {(pc & ~0xFFF) + imm:#x}", "adrp"
    # --- ADD / SUB immediate (sf 0 0 100010 sh imm12 Rn Rd) ------------------
    if (insn >> 23) & 0xFF == 0x22:
        op = "sub" if (insn >> 30) & 1 else "add"
        sh = (insn >> 22) & 1
        imm12 = (insn >> 10) & 0xFFF
        imm = imm12 << (12 if sh else 0)
        return (f"{op} {_a64_reg(Rd, sf)}, {_a64_base(Rn, sf)}, #{imm}",
                op)
    # --- MOVZ / MOVN / MOVK ------------------------------------------------------
    if (insn >> 23) & 0xFF in (0xA5, 0xE5) or \
            ((insn >> 23) & 0xFF) in (0xA5,):
        opc = (insn >> 23) & 3
        hw = (insn >> 21) & 3
        imm16 = (insn >> 5) & 0xFFFF
        mn = {0: "movn", 2: "movz", 3: "movk"}.get(opc, "mov?")
        return f"{mn} {_a64_reg(Rd, sf)}, #0x{imm16 << (16 * hw):x}", mn
    # --- LDR / STR unsigned imm -----------------------------------------------------
    if (insn >> 22) & 0x3BF == 0x39:
        size = insn >> 30
        L = (insn >> 22) & 1
        imm = ((insn >> 10) & 0xFFF) << size
        mn = "ldr" if L else "str"
        reg = _a64_reg(insn & 31, size == 3)
        return f"{mn} {reg}, [{_a64_base(Rn)}{f' + {imm:#x}' if imm else ''}]", mn
    # --- LDP / STP ------------------------------------------------------------------
    if (insn >> 25) in (0x29, 0xA9, 0x2B, 0xAB):
        V = (insn >> 26) & 1
        L = (insn >> 22) & 1
        opc = (insn >> 30) & 3
        imm7 = (insn >> 15) & 0x7F
        if imm7 & (1 << 6):
            imm7 -= 1 << 7
        scale = 3 if (V or opc == 1) else 2
        mn = "ldp" if L else "stp"
        rt = insn & 31
        rt2 = (insn >> 10) & 31
        t = "s" if V else ("x" if opc in (0, 2) else "w")
        off = imm7 << scale
        return (f"{mn} {t}{rt}, {t}{rt2}, "
                f"[{_a64_base(Rn)}, {off:+#x}]"), mn
    # --- logical shifted register (AND/ORR/EOR/ANDS) ----------------------------------
    if (insn >> 24) == 0x0A or (insn >> 24) == 0x4A:
        opc = (insn >> 29) & 7
        shift = (insn >> 22) & 3
        imm6 = (insn >> 10) & 63
        N = (insn >> 21) & 1
        mn = {0: "and", 1: "orr", 2: "eor", 3: "ands"}.get(opc, "and")
        if mn == "orr" and Rn == 31 and imm6 == 0 and shift == 0:
            return f"mov {_a64_reg(Rd, sf)}, {_a64_reg(Rm, sf)}", "mov"
        sh = {0: "lsl", 1: "lsr", 2: "asr"}.get(shift, "lsl")
        suffix = f", {sh} #{imm6}" if imm6 else ""
        return (f"{mn} {_a64_reg(Rd, sf)}, {_a64_reg(Rn, sf)}, "
                f"{_a64_reg(Rm, sf)}{suffix}"), mn
    # --- ORR shifted register (MOV alias) ------------------------------------------
    if (insn >> 24) == 0xAA:
        return f"orr {_a64_reg(Rd, sf)}, {_a64_reg(Rn, sf)}, " \
               f"{_a64_reg(Rm, sf)}", "orr"
    # --- NOP / SVC / HINT ------------------------------------------------------
    if insn == 0xD503201F:
        return "nop", "nop"
    if (insn & 0xFFE0001F) == 0xD4000001:
        return f"svc #{insn & 0xFF}", "svc"
    return f".word 0x{insn:08x}", "unknown"


def disassemble_arm64(data: bytes, base: int = 0,
                      limit: int = 4096) -> list[dict]:
    """Decode AArch64 instructions (4 bytes each, little-endian)."""
    rows: list[dict] = []
    n = min(len(data) // 4, limit)
    for i in range(n):
        off = i * 4
        (insn,) = struct.unpack_from("<I", data, off)
        text, mnem = _a64_one(insn, base + off)
        rows.append({"offset": off, "length": 4, "text": text,
                     "mnemonic": mnem})
    return rows


# ---------------------------------------------------------------------------
# public dispatch helpers
# ---------------------------------------------------------------------------

def detect_arch(data: bytes) -> str:
    """Guess instruction-set from magic bytes: 'arm64', 'x86', 'x64',
    'arm' (Thumb), or 'unknown'."""
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return "arm64" if b"\xcf\xfa\xed\xfe" == data[:4] else "arm64be"
    if data[:4] == b"\x7fELF":
        return "x64" if data[4] == 2 else "x86"
    if data[:2] == b"MZ":
        return "x64"  # nearly always x64 on modern Windows
    if data[:2] in (b"\x4d\x00",):  # Thumb
        return "arm"
    return "unknown"


def disassemble(data: bytes, arch: str, base: int = 0,
                limit: int = 4096) -> list[dict]:
    """Dispatch by arch ('x86', 'x64', 'arm64')."""
    if arch in ("x86", "x64"):
        return disassemble_x86(data, bitness=64 if arch == "x64" else 32,
                               base=base, limit=limit)
    if arch == "arm64":
        return disassemble_arm64(data, base=base, limit=limit)
    return []


def summarize_code(rows: list[dict]) -> dict:
    """Mnemonic histogram + call/jump target list for triage."""
    hist: dict[str, int] = {}
    calls: list[int] = []
    branches: list[int] = []
    for r in rows:
        hist[r["mnemonic"]] = hist.get(r["mnemonic"], 0) + 1
        if r["mnemonic"] in ("call", "bl", "blr"):
            target = None
            m = re_match_target(r["text"])
            if m:
                calls.append(int(m, 16))
        if r["mnemonic"].startswith(("j", "b.", "cb", "tb")):
            m = re_match_target(r["text"])
            if m:
                branches.append(int(m, 16))
    return {"mnemonics": dict(sorted(hist.items(), key=lambda kv: -kv[1])),
            "call_targets": calls, "branch_targets": branches,
            "instruction_count": len(rows)}


def re_match_target(text: str) -> str | None:
    """Extract the last hex target operand like '0x1234' from text."""
    import re
    m = re.search(r"0x[0-9a-f]+", text)
    return m.group(0) if m else None
