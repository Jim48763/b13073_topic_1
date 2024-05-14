rule fddaeadaeabcabfddaeedcefc_exe {
strings:
        $s1 = "Ty 2Q-%L YEo TqR "
        $s2 = "cxnme\\tcoU WoWnHee"
        $s3 = "RuntimeHelpersRuntimeHelpers"
        $s4 = "RuntimeHelpers"
        $s5 = "Q$sJlNt[_Otvt2"
        $s6 = "FVloSBsSeSIRfx"
        $s7 = "; Fr[ Roc vnVq"
        $s8 = "CooLeIlRpEo_rX"
        $s9 = "Y^K[_cf[*rS[Qd"
        $s10 = "cSekr]f'bWnXee"
        $s11 = "CTUIiPiHivljzZ"
        $s12 = "rrdFnJmorZtBW>"
        $s13 = "ol!UyeI nD>"
        $s14 = "SFLzC^ UaJe"
        $s15 = "tEpr=!WVn92"
        $s16 = "?Cxe_RBaZA<"
        $s17 = ">Lea_MBnKW<"
        $s18 = "yeO_waZdUnp"
        $s19 = "I)h0r+t.a?d"
        $s20 = "PaSfer_1=0&"
condition:
    uint16(0) == 0x5a4d and filesize < 572KB and
    4 of them
}
    
