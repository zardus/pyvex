import pyvex
import nose
import archinfo

def test_x86_aam():
    """
    Test generalized x86 aam instruction
    """
    irsb = pyvex.lift(b'\xd4\x0b', 0, archinfo.ArchX86())
    nose.tools.assert_equal(irsb.jumpkind,'Ijk_Boring')
    nose.tools.assert_equal(irsb.size, 2)

def test_x86_aad():
    """
    Test generalized x86 aad instruction
    """
    irsb = pyvex.lift(b'\xd5\x0b', 0, archinfo.ArchX86())
    nose.tools.assert_equal(irsb.jumpkind,'Ijk_Boring')
    nose.tools.assert_equal(irsb.size, 2)


if __name__ == '__main__':
    test_x86_aam()
    test_x86_aad()
