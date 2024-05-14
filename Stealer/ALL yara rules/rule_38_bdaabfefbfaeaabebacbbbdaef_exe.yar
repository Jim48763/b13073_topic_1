rule bdaabfefbfaeaabebacbbbdaef_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "english-caribbean"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "GetConsoleOutputCP"
        $s7 = "VarFileInfo"
        $s8 = "LC_MONETARY"
        $s9 = "SetVolumeLabelA"
        $s10 = "english-jamaica"
        $s11 = "`local vftable'"
        $s12 = "spanish-venezuela"
        $s13 = "GetThreadPriority"
        $s14 = "chinese-singapore"
        $s15 = "TerminateProcess"
        $s16 = "GetModuleHandleA"
        $s17 = "GetCurrentThreadId"
        $s18 = "GetLocalTime"
        $s19 = "south-africa"
        $s20 = " qN\\Z;zd>v!"
condition:
    uint16(0) == 0x5a4d and filesize < 282KB and
    4 of them
}
    
