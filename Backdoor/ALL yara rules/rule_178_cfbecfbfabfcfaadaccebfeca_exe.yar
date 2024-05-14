rule cfbecfbfabfcfaadaccebfeca_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "english-caribbean"
        $s3 = "GetEnvironmentStrings"
        $s4 = "invalid string position"
        $s5 = "GetConsoleOutputCP"
        $s6 = "LC_MONETARY"
        $s7 = "VarFileInfo"
        $s8 = "`local vftable'"
        $s9 = "sajbmianozu.iya"
        $s10 = "english-jamaica"
        $s11 = "spanish-venezuela"
        $s12 = "chinese-singapore"
        $s13 = "TerminateProcess"
        $s14 = "RemoveDirectoryW"
        $s15 = "GetModuleHandleW"
        $s16 = "EnterCriticalSection"
        $s17 = "south africa"
        $s18 = "GetTickCount"
        $s19 = "GetDevicePowerState"
        $s20 = "Unknown exception"
condition:
    uint16(0) == 0x5a4d and filesize < 293KB and
    4 of them
}
    
