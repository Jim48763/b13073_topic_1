rule bfbaffefccbbefceddacabfddc_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "`vector destructor iterator'"
        $s3 = "<file unknown>"
        $s4 = "meviroteguyesuxunu"
        $s5 = "IeP'Mm3Ag~,"
        $s6 = "H`p5AIC2Mfx"
        $s7 = "P)vCMf9xk\""
        $s8 = "VarFileInfo"
        $s9 = "SetVolumeLabelA"
        $s10 = "`local vftable'"
        $s11 = "GetThreadPriority"
        $s12 = "TerminateProcess"
        $s13 = "CreateJobObjectA"
        $s14 = "SetComputerNameA"
        $s15 = "GetModuleHandleW"
        $s16 = "EnterCriticalSection"
        $s17 = "WriteProfileSectionW"
        $s18 = "(((_Src))) != NULL"
        $s19 = "SetEndOfFile"
        $s20 = "Expression: "
condition:
    uint16(0) == 0x5a4d and filesize < 849KB and
    4 of them
}
    
