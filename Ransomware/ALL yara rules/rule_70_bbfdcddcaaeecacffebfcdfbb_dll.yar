rule bbfdcddcaaeecacffebfcdfbb_dll {
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
        $s17 = "`non-type-template-parameter"
        $s18 = "Unknown exception"
        $s19 = "norwegian-nynorsk"
        $s20 = "trinidad & tobago"
condition:
    uint16(0) == 0x5a4d and filesize < 786KB and
    4 of them
}
    
