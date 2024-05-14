rule beadeaeccfccdbfcea_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "english-caribbean"
        $s3 = "invalid string position"
        $s4 = "GetConsoleOutputCP"
        $s5 = "LC_MONETARY"
        $s6 = "rnJZ, eDNw'"
        $s7 = "`local vftable'"
        $s8 = "english-jamaica"
        $s9 = "spanish-venezuela"
        $s10 = "chinese-singapore"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleW"
        $s13 = "EnterCriticalSection"
        $s14 = "GetCurrentDirectoryA"
        $s15 = "SetEndOfFile"
        $s16 = "SetLocalTime"
        $s17 = "south africa"
        $s18 = "GetTickCount"
        $s19 = "IsBadWritePtr"
        $s20 = "Unknown exception"
condition:
    uint16(0) == 0x5a4d and filesize < 237KB and
    4 of them
}
    
