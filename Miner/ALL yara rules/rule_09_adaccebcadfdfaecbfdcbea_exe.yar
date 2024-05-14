rule adaccebcadfdfaecbfdcbea_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "invalid string position"
        $s5 = "oAFzL%i=n5@"
        $s6 = "VarFileInfo"
        $s7 = "LC_MONETARY"
        $s8 = "s) .'Szt2,#"
        $s9 = "english-jamaica"
        $s10 = "`local vftable'"
        $s11 = "SetVolumeLabelA"
        $s12 = "spanish-venezuela"
        $s13 = "SetComputerNameW"
        $s14 = "GetModuleHandleA"
        $s15 = "TerminateProcess"
        $s16 = "GetCurrentDirectoryA"
        $s17 = "GetCurrentThreadId"
        $s18 = "GetLocalTime"
        $s19 = "GetTickCount"
        $s20 = "south-africa"
condition:
    uint16(0) == 0x5a4d and filesize < 553KB and
    4 of them
}
    
