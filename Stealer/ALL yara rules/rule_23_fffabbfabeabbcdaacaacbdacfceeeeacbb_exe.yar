rule fffabbfabeabbcdaacaacbdacfceeeeacbb_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "english-caribbean"
        $s4 = "CoInitializeEx"
        $s5 = "invalid string position"
        $s6 = "LC_MONETARY"
        $s7 = "GetWindowDC"
        $s8 = "english-jamaica"
        $s9 = "`local vftable'"
        $s10 = "spanish-venezuela"
        $s11 = "chinese-singapore"
        $s12 = "RemoveDirectoryA"
        $s13 = "TerminateProcess"
        $s14 = "GetCurrentDirectoryW"
        $s15 = "GetCurrentThreadId"
        $s16 = "CreateCompatibleDC"
        $s17 = "GetLocalTime"
        $s18 = "south-africa"
        $s19 = "SetEndOfFile"
        $s20 = "FindFirstFileExA"
condition:
    uint16(0) == 0x5a4d and filesize < 281KB and
    4 of them
}
    
