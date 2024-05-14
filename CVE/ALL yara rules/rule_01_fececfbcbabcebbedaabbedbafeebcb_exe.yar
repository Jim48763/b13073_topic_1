rule fececfbcbabcebbedaabbedbafeebcb_exe {
strings:
        $s1 = "Directory not empty"
        $s2 = "Runtime Error!"
        $s3 = "invalid string position"
        $s4 = "No child processes"
        $s5 = "VarFileInfo"
        $s6 = "`local vftable'"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "Operation not permitted"
        $s10 = "GetCurrentDirectoryW"
        $s11 = "InitializeCriticalSection"
        $s12 = "VICEZAKOWUKEWOFEJAVE"
        $s13 = "GetCurrentThreadId"
        $s14 = "No locks available"
        $s15 = "Invalid seek"
        $s16 = "GetTickCount"
        $s17 = "Improper link"
        $s18 = "Unknown exception"
        $s19 = "Too many links"
        $s20 = "No such device"
condition:
    uint16(0) == 0x5a4d and filesize < 222KB and
    4 of them
}
    
