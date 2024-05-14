rule dcdecaaaeeeedcfededecb_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "GetEnvironmentStrings"
        $s5 = "invalid string position"
        $s6 = "GetConsoleOutputCP"
        $s7 = "Kristen ITC"
        $s8 = "LC_MONETARY"
        $s9 = "english-jamaica"
        $s10 = "`local vftable'"
        $s11 = "spanish-venezuela"
        $s12 = "TerminateProcess"
        $s13 = "Hear Them Speak!"
        $s14 = "DispatchMessageW"
        $s15 = "CreateCompatibleDC"
        $s16 = "GetCurrentThreadId"
        $s17 = "GetTickCount"
        $s18 = "Both Genders"
        $s19 = "south-africa"
        $s20 = "~[u(KZfCD'kZ"
condition:
    uint16(0) == 0x5a4d and filesize < 505KB and
    4 of them
}
    
