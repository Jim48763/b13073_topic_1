rule ccafffeedcfcecbebcbdbc_dll {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "(ch != _T('\\0'))"
        $s4 = "english-caribbean"
        $s5 = "GetEnvironmentStrings"
        $s6 = "__get_qualified_locale"
        $s7 = "=<=H=L=P=T=X=`=d=p=0>4>8>`>d>h>l>p>t>x>|>"
        $s8 = "<file unknown>"
        $s9 = "SetConsoleCtrlHandler"
        $s10 = "GetConsoleOutputCP"
        $s11 = "LC_MONETARY"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "spanish-venezuela"
        $s15 = "GetModuleHandleA"
        $s16 = "TerminateProcess"
        $s17 = "EnvironmentDirectory"
        $s18 = "_get_dstbias(&dstbias)"
        $s19 = "GetCurrentThreadId"
        $s20 = "(((_Src))) != NULL"
condition:
    uint16(0) == 0x5a4d and filesize < 517KB and
    4 of them
}
    
