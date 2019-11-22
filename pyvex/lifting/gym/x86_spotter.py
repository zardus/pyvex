from ..util.lifter_helper import GymratLifter
from ..util.instr_helper import Instruction
from ..util.vex_helper import Type
from .. import register
import logging

l = logging.getLogger(__name__)


class X86Instruction(Instruction): # pylint: disable=abstract-method
    pass

class Instruction_AAM(X86Instruction):
    name = "AAM"
    bin_format = '11010100iiiiiiii'
    # From https://www.felixcloutier.com/x86/aam
    def compute_result(self): # pylint: disable=arguments-differ
        base = self.constant(int(self.data['i'],2), Type.int_8)
        temp_al = self.get('al', Type.int_8)
        temp_ah = temp_al // base
        temp_al = temp_al % base
        self.put(temp_ah, 'ah')
        self.put(temp_al, 'al')
        l.warning("The generalized AAM instruction is not supported by VEX, and is handled specially by pyvex."
                  " It has no flag handling at present.  See pyvex/lifting/gym/x86_spotter.py for details")

    # TODO: Flags

class Instruction_AAD(X86Instruction):
    name = "AAD"
    bin_format = '11010101iiiiiiii'
    # From https://www.felixcloutier.com/x86/aad
    def compute_result(self): # pylint: disable=arguments-differ
        base = self.constant(int(self.data['i'],2), Type.int_8)
        temp_al = self.get('al', Type.int_8)
        temp_ah = self.get('ah', Type.int_8)
        temp_al = (temp_al + (temp_ah * base)) & 0xff 
        temp_ah = self.constant(0, Type.int_8)
        self.put(temp_ah, 'ah')
        self.put(temp_al, 'al')
        l.warning("The generalized AAM instruction is not supported by VEX, and is handled specially by pyvex."
                  " It has no flag handling at present.  See pyvex/lifting/gym/x86_spotter.py for details")
    # TODO: Flags

class Instruction_ENDBR(X86Instruction):
    name = "ENDBR"
    bin_format = '1111001100001111000111101111101b'

    def compute_result(self): # pylint: disable=arguments-differ
        # Perhaps, if one wanted to verify ENDBR behavior during compilation
        # Throw some CCall or whatever in here.
        if self.data['b'] == '1':
            l.debug("Ignoring ENDBR32 instruction at %#x.", self.addr)
        elif self.data['b'] == '0':
            l.debug("Ignoring ENDBR64 instruction at %#x.", self.addr)

class X86Spotter(GymratLifter):
    instrs = [
        Instruction_AAD,
        Instruction_AAM,
        Instruction_ENDBR]

register(X86Spotter, "X86")
register(X86Spotter, "AMD64")
