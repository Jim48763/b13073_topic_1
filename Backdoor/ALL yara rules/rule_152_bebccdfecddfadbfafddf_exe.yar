rule bebccdfecddfadbfafddf_exe {
strings:
        $s1 = "cropRectRightlong"
        $s2 = "GetConsoleOutputCP"
        $s3 = " 2\"/$IVcHZ"
        $s4 = "JfX|TR.I%)$"
        $s5 = "k>GTan%K}Q^"
        $s6 = "Vcp}bIhNAB]"
        $s7 = "X{IVcp}uh[N"
        $s8 = "%\"Z,;FS`EJ"
        $s9 = "\"KyZ]7?-Cw"
        $s10 = "\"byDY1)]jw"
        $s11 = "RP\"-<IV}*8"
        $s12 = "`8P\"/<IVAu"
        $s13 = "D&ILa1R*)%d"
        $s14 = "~aQ$b>KX=,9"
        $s15 = "!\"g/?IVcYJ"
        $s16 = "GetModuleHandleW"
        $s17 = "TerminateProcess"
        $s18 = "printSixteenBitbool"
        $s19 = "WriteProcessMemory"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 690KB and
    4 of them
}
    
