rule bacabafbefcafeafeacbaccaf_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "LoadAcceleratorsW"
        $s4 = "bad function call"
        $s5 = "english-caribbean"
        $s6 = "Runtime Error!"
        $s7 = "SetConsoleCtrlHandler"
        $s8 = "GetConsoleOutputCP"
        $s9 = "LoadStringW"
        $s10 = "4)S}mVd'Ppl"
        $s11 = "LC_MONETARY"
        $s12 = "1zuy~G\"as["
        $s13 = "english-jamaica"
        $s14 = "`local vftable'"
        $s15 = "DialogBoxParamW"
        $s16 = "spanish-venezuela"
        $s17 = "TerminateProcess"
        $s18 = "SetFilePointerEx"
        $s19 = "DispatchMessageW"
        $s20 = "SetThreadStackGuarantee"
condition:
    uint16(0) == 0x5a4d and filesize < 971KB and
    4 of them
}
    
