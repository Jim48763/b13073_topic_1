rule eacfacabbccbeebeafcbaeda_dll {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "Runtime Error!"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "LC_MONETARY"
        $s7 = "english-jamaica"
        $s8 = "`local vftable'"
        $s9 = "spanish-venezuela"
        $s10 = "TerminateProcess"
        $s11 = "SetFilePointerEx"
        $s12 = "SetThreadStackGuarantee"
        $s13 = "EventWriteTransfer"
        $s14 = "south-africa"
        $s15 = "FindFirstFileExW"
        $s16 = "IsValidLocale"
        $s17 = "2-2V2c2|2>3H3_3?4D4d4"
        $s18 = "`non-type-template-parameter"
        $s19 = "Unknown exception"
        $s20 = "norwegian-nynorsk"
condition:
    uint16(0) == 0x5a4d and filesize < 795KB and
    4 of them
}
    
