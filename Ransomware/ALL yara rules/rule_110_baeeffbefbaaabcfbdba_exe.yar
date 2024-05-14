rule baeeffbefbaaabcfbdba_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "GetEnvironmentStrings"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "GetConsoleOutputCP"
        $s7 = "T}jg>`J(\"V"
        $s8 = "VirtualLock"
        $s9 = "LC_MONETARY"
        $s10 = ";[y&_~Fm|B2"
        $s11 = ".t!h`#*w/gL"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "spanish-venezuela"
        $s15 = "AFX_DIALOG_LAYOUT"
        $s16 = "GetModuleHandleA"
        $s17 = "TerminateProcess"
        $s18 = "GetCurrentThreadId"
        $s19 = "GetConsoleAliasesW"
        $s20 = "GetLocalTime"
condition:
    uint16(0) == 0x5a4d and filesize < 833KB and
    4 of them
}
    
