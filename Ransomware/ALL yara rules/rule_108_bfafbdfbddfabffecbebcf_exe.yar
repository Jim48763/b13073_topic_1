rule bfafbdfbddfabffecbebcf_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "GetEnvironmentStrings"
        $s5 = "GetSystemPowerStatus"
        $s6 = "YOSIBALIBINIBUREWEHO"
        $s7 = "CreateIoCompletionPort"
        $s8 = "invalid string position"
        $s9 = "SetConsoleOutputCP"
        $s10 = "_husaberg@4"
        $s11 = "F-qy*;XkBRS"
        $s12 = "A&$J~XF[6\""
        $s13 = "LC_MONETARY"
        $s14 = "english-jamaica"
        $s15 = "`local vftable'"
        $s16 = "GetThreadPriority"
        $s17 = "spanish-venezuela"
        $s18 = "SetComputerNameW"
        $s19 = "GetModuleHandleA"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 742KB and
    4 of them
}
    
